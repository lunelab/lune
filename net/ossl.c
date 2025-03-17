/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2024 Lune Reseau, Inc.
 */

#include <openssl/opensslv.h>
#include <openssl/bio.h>

#if OPENSSL_VERSION_NUMBER < 0x10101000L
#error "openssl version not supported"
#endif

#include "lune/assert.h"
#include "lune/err.h"
#include "lune/idtable.h"
#include "lune/log.h"
#include "lune/mem.h"
#include "lune/ssl.h"

#include "err/err.h"
#include "lib/arrlist.h"
#include "lib/idlist.h"
#include "lib/idtable.h"
#include "lib/msgqueue.h"
#include "net/socket.h"
#include "net/ossl.h"
#include "rt/coproc.h"
#include "rt/core.h"

#define OSSL_DEFAULT_VERSION                    (LUNE_SSL_VERSION_TLS)

#define OSSL_SESS_CACHE_SIZE                    (4096)

typedef struct _ossl_async_req_hdr {
    ossl_ssl_t *ssl;
    socket_t *sk;
#define OSSL_ASYNC_REQ_TYPE_PKT_RECV            (0)
#define OSSL_ASYNC_REQ_TYPE_PKT_SEND            (1)
#define OSSL_ASYNC_REQ_TYPE_SOCKET_CLOSE        (2)
    unsigned int type;
    union {
        unsigned int close_type;    /* for OSSL_ASYNC_REQ_TYPE_SOCKET_CLOSE only */
    };
    unsigned char buf[0];
} ossl_async_req_hdr_t;

typedef struct _ossl_async_resp_hdr {
    ossl_ssl_t *ssl;
    socket_t *sk;
    int err;
#define OSSL_ASYNC_RESP_TYPE_SSL_EST            (0)
#define OSSL_ASYNC_RESP_TYPE_SSL_SEND_EST       (1)
#define OSSL_ASYNC_RESP_TYPE_SSL_SEND           (2)
#define OSSL_ASYNC_RESP_TYPE_SSL_RECV           (3)
#define OSSL_ASYNC_RESP_TYPE_SSL_RECV_MORE      (4)
/* OSSL_ASYNC_RESP_TYPE_SSL_ONGOING: do nothing but de-reference counters */
#define OSSL_ASYNC_RESP_TYPE_SSL_ONGOING        (5)
#define OSSL_ASYNC_RESP_TYPE_SSL_ACTIVE_CLOSE   (6)
#define OSSL_ASYNC_RESP_TYPE_SSL_PASSIVE_CLOSE  (7)
#define OSSL_ASYNC_RESP_TYPE_SSL_RST_CLOSE      (8)
#define OSSL_ASYNC_RESP_TYPE_SSL_QUIET_CLOSE    (9)
#define OSSL_ASYNC_RESP_TYPE_SSL_FAIL           (10)
    unsigned int type;
    union {
        /* for OSSL_ASYNC_RESP_TYPE_SSL_RECV(_MORE) only */
        unsigned int recv_len;
        /* for response with data or message to be sent by NP, representing data encrypted successfully */
        unsigned int send_len;
    };
    unsigned char buf[0];
} ossl_async_resp_hdr_t;

static __thread void *s_ossl_ctx_idlist = NULL;
static __thread void *s_ossl_ctx_idtable = NULL;

static __thread const unsigned char *s_ossl_recv_buf = NULL;
__thread unsigned int g_ossl_recv_left_len = 0;

#define OSSL_MAX_SEND_BUF_SIZE                  (65536 * 2)
__thread unsigned char *g_ossl_send_buf = NULL;
__thread unsigned int g_ossl_send_len = 0;

static __thread void *s_ossl_async_send_sslp = NULL;

static void ossl_cache_session(ossl_ssl_t *ossl_ssl);

static SSL_SESSION *ossl_alloc_cached_session(ossl_ctx_t *ctx);

static inline void ossl_send(const unsigned char *buf, unsigned int len)
{
#ifdef LUNE_DEBUG
    lune_assert((g_ossl_send_len + len) <= OSSL_MAX_SEND_BUF_SIZE);
#endif
    memcpy(g_ossl_send_buf + g_ossl_send_len, buf, len);
    g_ossl_send_len += len;
}

#define BIO_TYPE_LUNE_SOCKET                    (0x80 | BIO_TYPE_SOURCE_SINK)

static int ossl_write(BIO *h, const char *buf, int num);
static int ossl_read(BIO *h, char *buf, int size);
static long ossl_ctrl(BIO *h, int cmd, long arg1, void *arg2);
static int ossl_new(BIO *h);
static int ossl_free(BIO *data);

static __thread BIO_METHOD *ossl_method;

static const char *s_ossl_cipher_str_array[] = {
    TLS1_TXT_RSA_WITH_AES_128_SHA,
    TLS1_TXT_RSA_WITH_AES_256_SHA,
    SSL3_TXT_RSA_NULL_MD5,
    SSL3_TXT_RSA_NULL_SHA,
    TLS1_TXT_DHE_RSA_WITH_AES_128_SHA,
    TLS1_TXT_DHE_RSA_WITH_AES_256_SHA,
    TLS1_TXT_ADH_WITH_AES_128_SHA,
    TLS1_TXT_RSA_WITH_AES_128_SHA256,
    TLS1_TXT_RSA_WITH_AES_256_SHA256,
    TLS1_TXT_RSA_WITH_AES_128_GCM_SHA256,
    TLS1_TXT_RSA_WITH_AES_256_GCM_SHA384,
    TLS1_TXT_DHE_RSA_WITH_AES_256_SHA256,
    TLS1_TXT_ECDHE_RSA_WITH_AES_128_SHA256,
    TLS1_TXT_ECDHE_RSA_WITH_AES_256_SHA384,
    TLS1_TXT_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    TLS1_TXT_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    TLS1_TXT_ECDHE_ECDSA_WITH_AES_128_SHA256,
    TLS1_TXT_ECDHE_ECDSA_WITH_AES_256_SHA384,
};

static_assert(LUNE_SSL_CIPHER_MAX == (sizeof(s_ossl_cipher_str_array) / sizeof(const char *)),
    "SSL cipher type and name unmatched");

static BIO_METHOD *BIO_s_ossl(void)
{
    if (NULL == ossl_method) {
        ossl_method = BIO_meth_new(BIO_TYPE_LUNE_SOCKET, "lune socket");
        if (NULL == ossl_method
            || !BIO_meth_set_write(ossl_method, ossl_write)
            || !BIO_meth_set_read(ossl_method, ossl_read)
            || !BIO_meth_set_ctrl(ossl_method, ossl_ctrl)
            || !BIO_meth_set_create(ossl_method, ossl_new)
            || !BIO_meth_set_destroy(ossl_method, ossl_free)) {
            return NULL;
        }
    }
    return ossl_method;
}

static int ossl_new(BIO *b)
{
    BIO_set_init(b, 0);
    BIO_set_data(b, NULL);
    return 1;
}

static int ossl_free(BIO *b)
{
    if (NULL == b) {
        return 0;
    }

    if (BIO_get_shutdown(b)) {
        BIO_set_init(b, 0);
    }

    return 1;
}

static int ossl_read(BIO *b, char *out, int outl)
{
    int ret = -1;

    if (unlikely(NULL == out || 0 >= outl)) {
        lune_log(LUNE_INFO, "failed to receive ssl packet with size %d: %s",
            outl, ERR_GET_ERR_STR(ERR_SET_ERR(LUNE_ERR_INVALID_ARG)));
        goto END;
    }

    BIO_clear_retry_flags(b);
    if (0 == g_ossl_recv_left_len) {
        /*
            notify openssl:
            1. empty buffer
            2. non-blocking
        */
        BIO_set_retry_read(b);
        goto END;
    }

    ret = ((unsigned int)outl > g_ossl_recv_left_len) ? (int)g_ossl_recv_left_len : outl;
    memcpy(out, s_ossl_recv_buf, ret);
    s_ossl_recv_buf += ret;
    g_ossl_recv_left_len -= ret;
    if (0 == g_ossl_recv_left_len) {
        s_ossl_recv_buf = NULL;
    }

END:
    return ret;
}

static int ossl_write(BIO *b, const char *in, int inl)
{
    int ret = -1;

    if (unlikely(NULL == in || 0 >= inl)) {
        lune_log(LUNE_INFO, "failed to send ssl packet with size %d: %s",
            inl, ERR_GET_ERR_STR(ERR_SET_ERR(LUNE_ERR_INVALID_ARG)));
        goto END;
    }

    ossl_send((const unsigned char *)in, inl);
    if (CORE_IS_CP()) {
        OSSL_ASYNC_SEND_SET_ON(s_ossl_async_send_sslp);
    } else {
        OSSL_SYNC_SEND_SET_ON(BIO_get_data(b));
    }

    ret = inl;

END:
    return ret;
}

static long ossl_ctrl(BIO *b, int cmd, long num __attribute__((unused)), void *ptr)
{
    long ret = 1;

    switch (cmd) {
    case BIO_C_SET_FILE_PTR:
        lune_assert(NULL != ptr);
        BIO_set_init(b, 1);
        BIO_set_data(b, ptr);
        break;
    case BIO_C_GET_FILE_PTR:
        lune_assert(NULL != ptr);
        *(void **)ptr = BIO_get_data(b);
        break;
    case BIO_CTRL_FLUSH:
        ret = 1;
        break;
    case BIO_CTRL_PUSH:
    case BIO_CTRL_POP:
        ret = 0;
        break;
    default:
        lune_log(LUNE_INFO, "ssl command %d not supported by ssl oa bio", cmd);
        ret = 0;
        break;
    }

    return ret;
}

static inline void ossl_ssl_first_hold(ossl_ssl_t *ssl)
{
#ifdef LUNE_DEBUG
    lune_assert(0 == ssl->ref_cnt);
#endif
    ++ssl->ref_cnt;
}

static inline void ossl_ssl_hold(ossl_ssl_t *ssl)
{
#ifdef LUNE_DEBUG
    lune_assert(ssl->ref_cnt > 0);
#endif
    ++ssl->ref_cnt;
}

static inline void ossl_ssl_put(ossl_ssl_t *ssl)
{
#ifdef LUNE_DEBUG
    lune_assert(ssl->ref_cnt > 0);
#endif
    if (0 == --ssl->ref_cnt) {
        if (OSSL_IS_SESS_CACHE_SET(ssl)) {
            /* connection closed, session can be used for new connection */
            ossl_cache_session(ssl);
        }

        ossl_ctx_put(ssl->ctx);
        ssl->ctx = NULL;

        SSL_free(ssl->ssl);
        ssl->ssl = NULL;

        lune_free(ssl);
    }
}

void ossl_set_recv_pkt(const unsigned char *buf, unsigned int len)
{
#ifdef LUNE_DEBUG
    lune_assert(0 == g_ossl_recv_left_len);
#endif
    s_ossl_recv_buf = buf;
    g_ossl_recv_left_len = len;
}

int ossl_load_certificate(ossl_ctx_t *ctx, const char *cert_file, const char *priv_key)
{
#ifdef LUNE_DEBUG
    lune_assert(NULL != ctx->ctx);
    lune_assert(NULL != cert_file);
    lune_assert(NULL != priv_key);
#endif

    if (!SSL_CTX_use_certificate_file(ctx->ctx, cert_file, SSL_FILETYPE_PEM)) {
        lune_log(LUNE_INFO, "failed to set certificate file: %s",
            ERR_error_string(ERR_get_error(), NULL));
        return ERR_SET_ERR(LUNE_ERR_SSL_INTERNAL);
    }

    if (!SSL_CTX_use_PrivateKey_file(ctx->ctx, priv_key, SSL_FILETYPE_PEM)) {
        lune_log(LUNE_INFO, "failed to set private key file: %s",
            ERR_error_string(ERR_get_error(), NULL));
        return ERR_SET_ERR(LUNE_ERR_SSL_INTERNAL);
    }

    if (!SSL_CTX_check_private_key(ctx->ctx)) {
        lune_log(LUNE_INFO, "private key does not match the public certificate");
        return ERR_SET_ERR(LUNE_ERR_SSL_INTERNAL);
    }

    OSSL_CTX_SET_CERT(ctx);

    return 0;
}

int ossl_set_ciphers(ossl_ctx_t *ctx, lune_ssl_cipher_en *ciphers_array, unsigned int ciphers_num)
{
    unsigned int i;
    char cipher_list[LUNE_SSL_CIPHERS_MAX_NUM * 256];

#ifdef LUNE_DEBUG
    lune_assert(NULL != ctx->ctx);
    lune_assert(NULL != ciphers_array);
    lune_assert(ciphers_num > 0);
#endif

    if (ciphers_array[0] < 0 || ciphers_array[0] >= LUNE_SSL_CIPHER_MAX) {
        return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
    }

    strcpy(cipher_list, s_ossl_cipher_str_array[ciphers_array[0]]);

    for (i = 1; i < ciphers_num; i++) {
        if (ciphers_array[i] < 0 || ciphers_array[i] >= LUNE_SSL_CIPHER_MAX) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        strcat(cipher_list, ":");
        strcat(cipher_list, s_ossl_cipher_str_array[ciphers_array[i]]);
    }

    if (!SSL_CTX_set_cipher_list(ctx->ctx, cipher_list)
        /* TLS 1.3 and above */
        && !SSL_CTX_set_ciphersuites(ctx->ctx, cipher_list)) {
        lune_log(LUNE_INFO, "failed to set cipher list: %s", cipher_list);
        ERR_print_errors_fp(stderr);
        return ERR_SET_ERR(LUNE_ERR_SSL_INTERNAL);
    }

    return 0;
}

static int ossl_create_sess_cache_arrlist(ossl_ctx_t *ctx)
{
    char sess_cache_arrlist_name[LUNE_MAX_SHORT_NAME_BUF_LEN];

    sprintf(sess_cache_arrlist_name, "ssl session cache list %d", ctx->id);
    if (NULL == (ctx->sess_cache_arrlist = arrlist_create_s_list(sess_cache_arrlist_name,
        OSSL_SESS_CACHE_SIZE, sizeof(SSL_SESSION *)))) {
        return ERR_GET_LAST_ERR();
    }

    return 0;
}

static void ossl_delete_sess_cache_arrlist(ossl_ctx_t *ctx)
{
    void *n, *n2;

    ARRLIST_FOR_EACH_NODE_SAFE(ctx->sess_cache_arrlist, n, n2) {
        SSL_SESSION *sess = *(SSL_SESSION **)ARRLIST_GET_ELEM_BY_NODE(n);
        SSL_SESSION_free(sess);
        arrlist_s_list_free_elem(ctx->sess_cache_arrlist, ARRLIST_GET_ELEM_BY_NODE(n));
    }

    arrlist_delete_s_list(ctx->sess_cache_arrlist);
    ctx->sess_cache_arrlist = NULL;
}

int ossl_get_sess_cache_mode(ossl_ctx_t *ctx, lune_ssl_sess_cache_mode_en *mode)
{
    long ossl_mode = SSL_CTX_get_session_cache_mode(ctx->ctx);

    switch (ossl_mode) {
    case SSL_SESS_CACHE_OFF:
        *mode = LUNE_SSL_SESS_CACHE_OFF;
        break;
    case SSL_SESS_CACHE_CLIENT:
        *mode = LUNE_SSL_SESS_CACHE_CLIENT;
        break;
    case SSL_SESS_CACHE_SERVER:
        *mode = LUNE_SSL_SESS_CACHE_SERVER;
        break;
    default:
        /* other modes not supported for now */
        return ERR_SET_ERR(LUNE_ERR_SSL_INTERNAL);
    }

    return 0;
}

int ossl_set_sess_cache_mode(ossl_ctx_t *ctx, lune_ssl_sess_cache_mode_en mode)
{
    int err;
    long new_ossl_mode;
    lune_ssl_sess_cache_mode_en curr_mode;

    lune_assert(!ossl_get_sess_cache_mode(ctx, &curr_mode));
    if (mode == curr_mode) {
        return ERR_SET_ERR(LUNE_ERR_ALREADY_SET);
    }

    if ((LUNE_SSL_SESS_CACHE_SERVER == mode && OSSL_CTX_IS_CLIENT(ctx))
        || (LUNE_SSL_SESS_CACHE_CLIENT == mode && !OSSL_CTX_IS_CLIENT(ctx))) {
        return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
    }

    switch (mode) {
    case LUNE_SSL_SESS_CACHE_OFF:
        if (LUNE_SSL_SESS_CACHE_CLIENT == curr_mode) {
            lune_assert(NULL != ctx->sess_cache_arrlist);
            ossl_delete_sess_cache_arrlist(ctx);
        }

        new_ossl_mode = SSL_SESS_CACHE_OFF;
        break;
    case LUNE_SSL_SESS_CACHE_CLIENT:
        lune_assert(NULL == ctx->sess_cache_arrlist);
        if (0 != (err = ossl_create_sess_cache_arrlist(ctx))) {
            return err;
        }

        new_ossl_mode = SSL_SESS_CACHE_CLIENT;
        break;
    case LUNE_SSL_SESS_CACHE_SERVER:
        lune_assert(NULL == ctx->sess_cache_arrlist);
        new_ossl_mode = SSL_SESS_CACHE_SERVER;
        break;
    default:
        return ERR_SET_ERR(LUNE_ERR_SSL_INTERNAL);
    }

    (void)SSL_CTX_set_session_cache_mode(ctx->ctx, new_ossl_mode);

    lune_log(LUNE_DBG,
        "set session cache mode %d on ssl ctx %d, previous cache mode %d",
        mode,
        ctx->id,
        curr_mode);

    return 0;
}

unsigned int ossl_create_ctx(lune_ssl_version_en ver, lune_ssl_type_en type)
{
    ossl_ctx_t *ctx;

    if (NULL == (ctx = lune_malloc(sizeof(ossl_ctx_t)))) {
        goto ERR_1;
    }

    ctx->flags = 0;

    if (LUNE_SSL_CLIENT == type) {
        if (NULL == (ctx->ctx = SSL_CTX_new(TLS_client_method()))) {
            ERR_SET_ERR(LUNE_ERR_SSL_INTERNAL);
            goto ERR_2;
        }

        OSSL_CTX_SET_CLIENT(ctx);
    } else {
        /* LUNE_SSL_SERVER */
        if (NULL == (ctx->ctx = SSL_CTX_new(TLS_server_method()))) {
            ERR_SET_ERR(LUNE_ERR_SSL_INTERNAL);
            goto ERR_2;
        }

        OSSL_CTX_SET_SERVER(ctx);
    }

    /* support down to the lowest ever possible */
    if (unlikely(!SSL_CTX_set_min_proto_version(ctx->ctx, 0))) {
        ERR_SET_ERR(LUNE_ERR_SSL_INTERNAL);
        goto ERR_3;
    }

    switch (ver) {
    case LUNE_SSL_VERSION_SSLV3:
        if (unlikely(!SSL_CTX_set_max_proto_version(ctx->ctx, SSL3_VERSION))) {
            ERR_SET_ERR(LUNE_ERR_SSL_INTERNAL);
            goto ERR_3;
        }
        break;
    case LUNE_SSL_VERSION_TLSV1:
        if (unlikely(!SSL_CTX_set_max_proto_version(ctx->ctx, TLS1_VERSION))) {
            ERR_SET_ERR(LUNE_ERR_SSL_INTERNAL);
            goto ERR_3;
        }
        break;
    case LUNE_SSL_VERSION_TLSV1_1:
        if (unlikely(!SSL_CTX_set_max_proto_version(ctx->ctx, TLS1_1_VERSION))) {
            ERR_SET_ERR(LUNE_ERR_SSL_INTERNAL);
            goto ERR_3;
        }
        break;
    case LUNE_SSL_VERSION_TLSV1_2:
        if (unlikely(!SSL_CTX_set_max_proto_version(ctx->ctx, TLS1_2_VERSION))) {
            ERR_SET_ERR(LUNE_ERR_SSL_INTERNAL);
            goto ERR_3;
        }
        break;
    case LUNE_SSL_VERSION_TLS:
    case LUNE_SSL_VERSION_TLSV1_3:
        if (unlikely(!SSL_CTX_set_max_proto_version(ctx->ctx, TLS1_3_VERSION))) {
            ERR_SET_ERR(LUNE_ERR_SSL_INTERNAL);
            goto ERR_3;
        }
        break;
    default:
        ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        goto ERR_3;
    }

    if (LUNE_INVALID_ID == (ctx->id = idlist_get_new_id(s_ossl_ctx_idlist))) {
        goto ERR_3;
    }

    if (0 != idtable_insert(ctx->id, ctx, s_ossl_ctx_idtable)) {
        goto ERR_4;
    }

    ctx->ref_cnt = 0;
    ossl_ctx_first_hold(ctx);

    ctx->rsvd = 0;
    ctx->sess_cache_arrlist = NULL;

    return ctx->id;

ERR_4:
    lune_assert(!idlist_del_id(ctx->id, s_ossl_ctx_idlist));

ERR_3:
    SSL_CTX_free(ctx->ctx);
    ctx->ctx = NULL;

ERR_2:
    lune_free(ctx);

ERR_1:
    return LUNE_INVALID_ID;
}

int ossl_delete_ctx(unsigned int id)
{
    ossl_ctx_t *ctx;

    if (NULL == (ctx = (ossl_ctx_t *)idtable_find(id, s_ossl_ctx_idtable))) {
        return ERR_SET_ERR(LUNE_ERR_ID_NOT_FOUND);
    }

    if (NULL != ctx->sess_cache_arrlist) {
        ossl_delete_sess_cache_arrlist(ctx);
    }

    lune_assert(!idtable_remove(id, s_ossl_ctx_idtable));
    lune_assert(!idlist_del_id(id, s_ossl_ctx_idlist));

    ctx->id = LUNE_INVALID_ID;
    ossl_ctx_put(ctx);
    return 0;
}

ossl_ctx_t *ossl_get_ctx(unsigned int id)
{
    ossl_ctx_t *ctx;

    if (NULL == (ctx = (ossl_ctx_t *)idtable_find(id, s_ossl_ctx_idtable))) {
        return NULL;
    }

#ifdef LUNE_DEBUG
    lune_assert(ctx->ctx != NULL);
#endif

    return ctx;
}

static void ossl_free_ctx(ossl_ctx_t *ctx)
{
    ossl_ctx_put(ctx);
}

ossl_ssl_t *ossl_create_ssl(ossl_ctx_t *ctx)
{
    ossl_ssl_t *ssl;
    SSL_SESSION *sess;

    lune_assert(CORE_IS_NP());
#ifdef LUNE_DEBUG
    lune_assert(NULL != ctx->ctx);
#endif

    if (NULL == (ssl = lune_malloc(sizeof(ossl_ssl_t)))) {
        goto ERR_1;
    }

    if (NULL == (ssl->ssl = SSL_new(ctx->ctx))) {
        goto ERR_2;
    }

    if (NULL == (ssl->bio = BIO_new(BIO_s_ossl()))) {
        goto ERR_3;
    }

    BIO_set_fp(ssl->bio, ssl, BIO_NOCLOSE);
    SSL_set_bio(ssl->ssl, ssl->bio, ssl->bio);

    ssl->ctx = ctx;
    ossl_ctx_hold(ctx);

    ssl->sess = NULL;
    if (OSSL_IS_SESS_CACHE_SET(ssl)) {
        if (NULL != (sess = ossl_alloc_cached_session(ssl->ctx))) {
            lune_assert(SSL_set_session(ssl->ssl, sess));
        }
    }

    ssl->flags = ssl->cp_flags = 0;
    ssl->ref_cnt = 0;

    ossl_ssl_first_hold(ssl);

    return ssl;

ERR_3:
    SSL_free(ssl->ssl);

ERR_2:
    lune_free(ssl);

ERR_1:
    return NULL;
}

void ossl_delete_ssl(ossl_ssl_t *ssl)
{
#ifdef LUNE_DEBUG
    lune_assert(!OSSL_DELETE_ON(ssl));
#endif
    OSSL_DELETE_SET_ON(ssl);
    ossl_ssl_put(ssl);
}

int ossl_async_handle_recv_pkt(ossl_ssl_t *ssl,
    void *sk, const unsigned char *buf, unsigned int len, unsigned int cp_idx)
{
    ossl_async_req_hdr_t *hdr;

    if (NULL == (hdr = (ossl_async_req_hdr_t *)core_get_coproc_req_buf(cp_idx,
        COPROC_REQ_TYPE_SSL, sizeof(ossl_async_req_hdr_t) + len))) {
        return ERR_GET_LAST_ERR();
    }

    hdr->ssl = ssl;
    ossl_ssl_hold(ssl);
    hdr->sk = sk;
    hdr->type = OSSL_ASYNC_REQ_TYPE_PKT_RECV;
    memcpy(hdr->buf, buf, len);

    core_coproc_req_buf_done(cp_idx);

    return 0;
}

int ossl_async_handle_send_pkt(ossl_ssl_t *ssl,
    void *sk, const unsigned char *buf, unsigned int len, unsigned int cp_idx)
{
    ossl_async_req_hdr_t *hdr;

    if (NULL == (hdr = (ossl_async_req_hdr_t *)core_get_coproc_req_buf(cp_idx,
        COPROC_REQ_TYPE_SSL, sizeof(ossl_async_req_hdr_t) + len))) {
        return ERR_GET_LAST_ERR();
    }

    hdr->ssl = ssl;
    ossl_ssl_hold(ssl);
    hdr->sk = sk;
    hdr->type = OSSL_ASYNC_REQ_TYPE_PKT_SEND;
    memcpy(hdr->buf, buf, len);

    core_coproc_req_buf_done(cp_idx);

    return 0;
}

int ossl_async_close_socket(ossl_ssl_t *ssl, void *sk, unsigned int cp_idx, unsigned int close_type)
{
    ossl_async_req_hdr_t *hdr;

    if (NULL == (hdr = (ossl_async_req_hdr_t *)core_get_coproc_req_buf(cp_idx,
        COPROC_REQ_TYPE_SSL, sizeof(ossl_async_req_hdr_t)))) {
        return ERR_GET_LAST_ERR();
    }

    hdr->ssl = ssl;
    ossl_ssl_hold(ssl);
    hdr->sk = sk;
    hdr->type = OSSL_ASYNC_REQ_TYPE_SOCKET_CLOSE;
    hdr->close_type = close_type;

    core_coproc_req_buf_done(cp_idx);

    return 0;
}

static inline int ossl_async_send_resp_with_data(ossl_ssl_t *ssl,
    socket_t *sk, int err, unsigned int type, unsigned int send_len, const unsigned char *buf, unsigned int len)
{
    ossl_async_resp_hdr_t *resp_hdr;

#ifdef LUNE_DEBUG
    lune_assert(OSSL_ASYNC_SEND_ON(ssl));
#endif
    OSSL_ASYNC_SEND_SET_OFF(ssl);

    if (NULL == (resp_hdr = (ossl_async_resp_hdr_t *)coproc_get_resp_buf(
        COPROC_RESP_TYPE_SSL, sizeof(ossl_async_resp_hdr_t) + len))) {
        /* NP overloaded */
        lune_log_once(LUNE_INFO, "failed to get buffer for ssl asynchronous response: %s",
            ERR_GET_LAST_ERR_STR());
        return ERR_GET_LAST_ERR();
    }

    memcpy(resp_hdr->buf, buf, len);
    resp_hdr->ssl = ssl;
    resp_hdr->sk = sk;
    resp_hdr->err = err;
    resp_hdr->type = type;
    resp_hdr->send_len = send_len;

    coproc_resp_buf_done();

    return 0;
}

static inline int ossl_async_send_resp_without_data(ossl_ssl_t *ssl, socket_t *sk, int err, unsigned int type)
{
    ossl_async_resp_hdr_t *resp_hdr;

#ifdef LUNE_DEBUG
    lune_assert(!OSSL_ASYNC_SEND_ON(ssl));
#endif

    if (NULL == (resp_hdr = (ossl_async_resp_hdr_t *)coproc_get_resp_buf(
        COPROC_RESP_TYPE_SSL, sizeof(ossl_async_resp_hdr_t)))) {
        /* NP overloaded */
        lune_log_once(LUNE_INFO, "failed to get buffer for ssl asynchronous response: %s",
            ERR_GET_LAST_ERR_STR());
        return ERR_GET_LAST_ERR();
    }

    resp_hdr->ssl = ssl;
    resp_hdr->sk = sk;
    resp_hdr->err = err;
    resp_hdr->type = type;

    coproc_resp_buf_done();

    return 0;
}

static inline int ossl_handle_coproc_pkt_recv_req(ossl_ssl_t *ssl,
    socket_t *sk, const unsigned char *buf, unsigned int len)
{
    int err, recv_len, dec_len;
    ossl_status_en status;
    ossl_async_resp_hdr_t *resp_hdr;
    unsigned char *recv_buf;
    unsigned int type;

#ifdef LUNE_DEBUG
    lune_assert(0 == g_ossl_recv_left_len);
    lune_assert(!OSSL_ASYNC_SEND_ON(ssl));
#endif

    s_ossl_recv_buf = buf;
    g_ossl_recv_left_len = len;

    s_ossl_async_send_sslp = ssl;
    g_ossl_send_len = 0;

    if (!OSSL_IS_INIT_FINISHED(ssl)) {
        if (OSSL_IS_CLIENT(ssl)) {
            err = OSSL_CONNECT(ssl);
        } else {
            err = OSSL_ACCEPT(ssl);
        }

        status = ossl_get_status(ssl, &err);
        switch (status) {
        case OSSL_STATUS_OK:
        case OSSL_STATUS_WANT_IO:
        case OSSL_STATUS_SHUTDOWN:
            break;
        default:
            lune_log(LUNE_INFO, "unexpected ssl oa status %d with ssl error %d on connection %s",
                status, err, tcp_print_pcb_4tuple(sk->pcb.ssl.tcp_pcb));

            g_ossl_recv_left_len = g_ossl_send_len = 0;
            s_ossl_async_send_sslp = NULL;

            return ossl_async_send_resp_without_data(ssl,
                sk, ERR_SET_ERR(LUNE_ERR_SSL_INTERNAL), OSSL_ASYNC_RESP_TYPE_SSL_FAIL);
        }

#ifdef LUNE_DEBUG
        lune_assert(0 == g_ossl_recv_left_len);
#endif

        if (OSSL_ASYNC_SEND_ON(ssl)) {
            lune_assert(status != OSSL_STATUS_SHUTDOWN);
            if (OSSL_IS_INIT_FINISHED(ssl)) {
                type = OSSL_ASYNC_RESP_TYPE_SSL_SEND_EST;
            } else {
                type = OSSL_ASYNC_RESP_TYPE_SSL_SEND;
            }

            err = ossl_async_send_resp_with_data(ssl, sk, err, type, 0, g_ossl_send_buf, g_ossl_send_len);

            g_ossl_send_len = 0;
            s_ossl_async_send_sslp = NULL;

            return err;
        }

#ifdef LUNE_DEBUG
        lune_assert(0 == g_ossl_send_len);
#endif

        if (OSSL_STATUS_SHUTDOWN == status) {
            type = OSSL_ASYNC_RESP_TYPE_SSL_PASSIVE_CLOSE;
        } else if (OSSL_IS_INIT_FINISHED(ssl)) {
            type = OSSL_ASYNC_RESP_TYPE_SSL_EST;
        } else {
            /* decryption in progress, waiting for further packet */
            type = OSSL_ASYNC_RESP_TYPE_SSL_ONGOING;
        }

        if (NULL == (resp_hdr = (ossl_async_resp_hdr_t *)coproc_get_resp_buf(
            COPROC_RESP_TYPE_SSL, sizeof(ossl_async_resp_hdr_t)))) {
            /* NP overloaded */
            lune_log_once(LUNE_INFO, "failed to get buffer for ssl asynchronous response: %s",
                ERR_GET_LAST_ERR_STR());
            s_ossl_async_send_sslp = NULL;
            return ERR_GET_LAST_ERR();
        }

        resp_hdr->ssl = ssl;
        resp_hdr->sk = sk;
        resp_hdr->err = err;
        resp_hdr->type = type;

        coproc_resp_buf_done();

        s_ossl_async_send_sslp = NULL;
        return 0;
    }

DECODE:
    if (NULL == (resp_hdr = (ossl_async_resp_hdr_t *)coproc_get_resp_buf(
        COPROC_RESP_TYPE_SSL,
        sizeof(ossl_async_resp_hdr_t) + SSL_RECV_DECRYPTED_PKT_MAX_SIZE))) {
        /* NP overloaded */
        lune_log_once(LUNE_INFO, "failed to get buffer for ssl asynchronous response: %s",
            ERR_GET_LAST_ERR_STR());
        g_ossl_recv_left_len = 0;
        s_ossl_async_send_sslp = NULL;
        return ERR_GET_LAST_ERR();
    }

    resp_hdr->ssl = ssl;
    resp_hdr->sk = sk;

    recv_buf = resp_hdr->buf;
    dec_len = 0;
    do {
        recv_len = OSSL_RECV(ssl, recv_buf, SSL_RECV_DECRYPTED_PKT_MAX_SIZE - dec_len);
        if (recv_len <= 0) {
            break;
        }

        dec_len += recv_len;
        recv_buf += recv_len;
    } while (!OSSL_IS_RECV_DONE()
        && (SSL_RECV_DECRYPTED_PKT_MAX_SIZE - dec_len) > 0);

    if (0 == dec_len) {
        lune_assert(recv_len <= 0);
        err = recv_len;
        status = ossl_get_status(ssl, &err);
        switch (status) {
        case OSSL_STATUS_WANT_IO:
            /* decryption in progress, waiting for further packet */
            resp_hdr->type = OSSL_ASYNC_RESP_TYPE_SSL_ONGOING;
            break;
        case OSSL_STATUS_SHUTDOWN:
            resp_hdr->type = OSSL_ASYNC_RESP_TYPE_SSL_PASSIVE_CLOSE;
            break;
        default:
            lune_assert(0);
            /* fall through */
        case OSSL_STATUS_FAIL:
            lune_log(LUNE_INFO, "failed to decrypt ssl data due to SSL error %d on connection %s",
                err, tcp_print_pcb_4tuple(sk->pcb.ssl.tcp_pcb));
            resp_hdr->type = OSSL_ASYNC_RESP_TYPE_SSL_FAIL;
            break;
        }
    } else {
        if (recv_len < 0) {
            err = recv_len;
            status = ossl_get_status(ssl, &err);
            switch (status) {
            case OSSL_STATUS_WANT_IO:
                recv_len = 0;
                resp_hdr->type = OSSL_ASYNC_RESP_TYPE_SSL_RECV;
                break;
            case OSSL_STATUS_SHUTDOWN:
                resp_hdr->type = OSSL_ASYNC_RESP_TYPE_SSL_PASSIVE_CLOSE;
                break;
            default:
                lune_assert(0);
                /* fall through */
            case OSSL_STATUS_FAIL:
                lune_log(LUNE_INFO, "failed to decrypt ssl data due to SSL error %d on connection %s",
                    err, tcp_print_pcb_4tuple(sk->pcb.ssl.tcp_pcb));
                resp_hdr->type = OSSL_ASYNC_RESP_TYPE_SSL_FAIL;
                break;
            }
        } else {
            recv_len = 0;
            resp_hdr->type = OSSL_ASYNC_RESP_TYPE_SSL_RECV;
        }
    }

    resp_hdr->err = recv_len;
    resp_hdr->recv_len = dec_len;

#ifdef LUNE_DEBUG
    lune_assert(SSL_RECV_DECRYPTED_PKT_MAX_SIZE - dec_len >= 0);
#endif

    if (!OSSL_IS_RECV_DONE()
        /*
            all data has been decrypted but buffer limit has hit, which
            means it is very likely that some decrypted data still remains
            to be received. hence one last DECODE is needed to retrieve it
        */
        || SSL_RECV_DECRYPTED_PKT_MAX_SIZE == dec_len) {
        lune_assert(OSSL_ASYNC_RESP_TYPE_SSL_RECV == resp_hdr->type);
        resp_hdr->type = OSSL_ASYNC_RESP_TYPE_SSL_RECV_MORE;
        coproc_resp_buf_done();
        goto DECODE;
    }

#ifdef LUNE_DEBUG
    lune_assert(0 == g_ossl_recv_left_len);
#endif

    if (unlikely(OSSL_ASYNC_SEND_ON(ssl))) {
        /*
            something may have gone wrong during decryption, sending alert
            keep an eye to see if any other message will be sent during
            decryption
        */

        if (dec_len > 0) {
            /* send decrypted data first, alert message will follow... */
            lune_assert(OSSL_ASYNC_RESP_TYPE_SSL_RECV == resp_hdr->type);
            resp_hdr->type = OSSL_ASYNC_RESP_TYPE_SSL_RECV_MORE;
            coproc_resp_buf_done();
        } else {
            /* no data decrypted, just release buffer */
            lune_assert(OSSL_ASYNC_RESP_TYPE_SSL_FAIL == resp_hdr->type);
            coproc_resp_buf_free();
        }

        lune_log(LUNE_INFO, "sending message with size %d after decrypting received data of %d bytes",
            g_ossl_send_len, len);

        err = ossl_async_send_resp_with_data(ssl,
            sk, 0, OSSL_ASYNC_RESP_TYPE_SSL_SEND, 0, g_ossl_send_buf, g_ossl_send_len);

        g_ossl_send_len = 0;
        s_ossl_async_send_sslp = NULL;

        return err;
    }

    coproc_resp_buf_done();

#ifdef LUNE_DEBUG
    lune_assert(0 == g_ossl_send_len);
#endif

    s_ossl_async_send_sslp = NULL;

    return 0;
}

static inline int ossl_handle_coproc_pkt_send_req(ossl_ssl_t *ssl,
    socket_t *sk, const unsigned char *buf, unsigned int len)
{
    int sent_len, err;

#ifdef LUNE_DEBUG
    lune_assert(OSSL_IS_INIT_FINISHED(ssl));
    lune_assert(!OSSL_ASYNC_SEND_ON(ssl));
#endif

    s_ossl_async_send_sslp = ssl;
    g_ossl_send_len = 0;

    sent_len = OSSL_SEND(ssl, buf, len);
    lune_assert((unsigned int)sent_len == len);
#ifdef LUNE_DEBUG
    lune_assert(0 != g_ossl_send_len);
#endif

    err = ossl_async_send_resp_with_data(ssl,
        sk, 0, OSSL_ASYNC_RESP_TYPE_SSL_SEND, sent_len, g_ossl_send_buf, g_ossl_send_len);

    g_ossl_send_len = 0;
    s_ossl_async_send_sslp = NULL;

    return err;
}

static inline int ossl_handle_coproc_socket_close_req(ossl_ssl_t *ssl,
    socket_t *sk, unsigned int close_type)
{
    int err;

    if (SSL_CLOSE_TYPE_RST == close_type) {
        /* do nothing */
        return ossl_async_send_resp_without_data(ssl, sk, 0, OSSL_ASYNC_RESP_TYPE_SSL_RST_CLOSE);
    }

    if (SSL_CLOSE_TYPE_QUIET == close_type) {
        /* do nothing */
        return ossl_async_send_resp_without_data(ssl, sk, 0, OSSL_ASYNC_RESP_TYPE_SSL_QUIET_CLOSE);
    }

#ifdef LUNE_DEBUG
    lune_assert(SSL_CLOSE_TYPE_NORMAL == close_type);
#endif

    s_ossl_async_send_sslp = ssl;
    g_ossl_send_len = 0;

    err = OSSL_CLOSE(ssl);
    if (unlikely(0 > err)) {
        lune_log(LUNE_INFO, "failed to close ssl connection %s due to SSL error %d",
            tcp_print_pcb_4tuple(sk->pcb.ssl.tcp_pcb),
            err);

        err = ossl_async_send_resp_without_data(ssl,
            sk, ERR_SET_ERR(LUNE_ERR_SSL_INTERNAL), OSSL_ASYNC_RESP_TYPE_SSL_FAIL);

        g_ossl_send_len = 0;
        s_ossl_async_send_sslp = NULL;

        return err;
    }

    lune_assert(OSSL_ASYNC_SEND_ON(sk->pcb.ssl.ossl_ssl));
    err = ossl_async_send_resp_with_data(ssl,
        sk, 0, OSSL_ASYNC_RESP_TYPE_SSL_ACTIVE_CLOSE, 0, g_ossl_send_buf, g_ossl_send_len);

    g_ossl_send_len = 0;
    s_ossl_async_send_sslp = NULL;

    return err;
}

int ossl_handle_coproc_req(const unsigned char *req, unsigned int req_len)
{
    const ossl_async_req_hdr_t *req_hdr = (const ossl_async_req_hdr_t *)req;

#ifdef LUNE_DEBUG
    lune_assert(0 == g_ossl_recv_left_len);
    lune_assert(0 == g_ossl_send_len);
    lune_assert(!OSSL_ASYNC_SEND_ON(req_hdr->ssl));
#endif

    switch (req_hdr->type) {
    case OSSL_ASYNC_REQ_TYPE_PKT_RECV:
        return ossl_handle_coproc_pkt_recv_req(req_hdr->ssl,
            req_hdr->sk, req_hdr->buf, req_len - sizeof(ossl_async_req_hdr_t));
    case OSSL_ASYNC_REQ_TYPE_PKT_SEND:
        return ossl_handle_coproc_pkt_send_req(req_hdr->ssl,
            req_hdr->sk, req_hdr->buf, req_len - sizeof(ossl_async_req_hdr_t));
    case OSSL_ASYNC_REQ_TYPE_SOCKET_CLOSE:
        return ossl_handle_coproc_socket_close_req(req_hdr->ssl, req_hdr->sk, req_hdr->close_type);
    default:
        lune_assert(0);
        return ERR_SET_ERR(LUNE_ERR_SSL_INTERNAL);
    }
}

int ossl_handle_coproc_resp(const unsigned char *resp, unsigned int resp_len)
{
    const ossl_async_resp_hdr_t *resp_hdr = (const ossl_async_resp_hdr_t *)resp;
    int err = 0;
    unsigned short cp_req_cnt = --resp_hdr->sk->pcb.ssl.cp_req_cnt;

    if (unlikely(OSSL_DELETE_ON(resp_hdr->ssl))) {
        /* skip response since ssl has been deleted */
        goto DONE;
    }

    switch (resp_hdr->type) {
    case OSSL_ASYNC_RESP_TYPE_SSL_EST:
        if (0 != (err = ssl_async_handle_conn_established(resp_hdr->sk, resp_hdr->ssl))) {
            goto DONE;
        }

        lune_assert(!OSSL_ASYNC_SEND_ON(resp_hdr->ssl));
        break;
    case OSSL_ASYNC_RESP_TYPE_SSL_SEND_EST:
        if (0 != (err = ssl_async_send(resp_hdr->sk,
            resp_hdr->buf, resp_len - sizeof(ossl_async_resp_hdr_t), resp_hdr->send_len))) {
            goto DONE;
        }

        if (0 != (err = ssl_async_handle_conn_established(resp_hdr->sk, resp_hdr->ssl))) {
            goto DONE;
        }

        lune_assert(!OSSL_ASYNC_SEND_ON(resp_hdr->ssl));
        break;
    case OSSL_ASYNC_RESP_TYPE_SSL_SEND:
        if (0 != (err = ssl_async_send(resp_hdr->sk,
            resp_hdr->buf, resp_len - sizeof(ossl_async_resp_hdr_t), resp_hdr->send_len))) {
            goto DONE;
        }
        break;
    case OSSL_ASYNC_RESP_TYPE_SSL_RECV_MORE:
        /* hold ssl & sk for more response from CP */
        ossl_ssl_hold(resp_hdr->ssl);
        resp_hdr->sk->pcb.ssl.cp_req_cnt++;
        socket_hold(resp_hdr->sk);
        /* fall through */
    case OSSL_ASYNC_RESP_TYPE_SSL_RECV:
        if (0 != (err = ssl_async_recv(resp_hdr->sk,
            resp_hdr->ssl, resp_hdr->buf, resp_hdr->recv_len, resp_hdr->err))) {
            goto DONE;
        }
        break;
    case OSSL_ASYNC_RESP_TYPE_SSL_ONGOING:
        /* do nothing */
        break;
    case OSSL_ASYNC_RESP_TYPE_SSL_ACTIVE_CLOSE:
        err = ssl_async_normal_close(resp_hdr->sk,
            resp_hdr->buf, resp_len - sizeof(ossl_async_resp_hdr_t));
        goto DONE;
    case OSSL_ASYNC_RESP_TYPE_SSL_PASSIVE_CLOSE:
        err = ssl_async_passive_close(resp_hdr->sk);
        goto DONE;
    case OSSL_ASYNC_RESP_TYPE_SSL_RST_CLOSE:
        err = ssl_async_reset_close(resp_hdr->sk);
        goto DONE;
    case OSSL_ASYNC_RESP_TYPE_SSL_QUIET_CLOSE:
        err = ssl_async_quiet_close(resp_hdr->sk);
        goto DONE;
    case OSSL_ASYNC_RESP_TYPE_SSL_FAIL:
        /* keep an eye on this */
        break;
    default:
        lune_assert(0);
        break;
    }

    if (0 == cp_req_cnt && SSL_IS_TCP_CLWAIT(&resp_hdr->sk->pcb.ssl)) {
        err = ssl_async_tcp_close(resp_hdr->sk);
    }

DONE:
    ossl_ssl_put(resp_hdr->ssl);
    socket_put(resp_hdr->sk);
    return err;
}

const char *ossl_get_cipher_str(lune_ssl_cipher_en cipher)
{
    return s_ossl_cipher_str_array[cipher];
}

void ossl_save_session(ossl_ssl_t *ossl_ssl)
{
    SSL_SESSION *sess;

    if (NULL == (sess = SSL_get1_session(ossl_ssl->ssl))) {
        return;
    }

    ossl_ssl->sess = sess;
}

void ossl_unsave_session(ossl_ssl_t *ossl_ssl)
{
    if (NULL != ossl_ssl->sess) {
        SSL_SESSION_free(ossl_ssl->sess);
        ossl_ssl->sess = NULL;
    }
}

static void ossl_cache_session(ossl_ssl_t *ossl_ssl)
{
    SSL_SESSION **sessp;

    if (unlikely(NULL == ossl_ssl->sess)) {
        return;
    }

    if (NULL == (sessp = arrlist_s_list_alloc_elem(ossl_ssl->ctx->sess_cache_arrlist))) {
        /* cache full */
        SSL_SESSION_free(ossl_ssl->sess);
        ossl_ssl->sess = NULL;
        return;
    }

    *sessp = ossl_ssl->sess;
    ossl_ssl->sess = NULL;
}

static SSL_SESSION *ossl_alloc_cached_session(ossl_ctx_t *ctx)
{
    SSL_SESSION *sess, **sessp;

    if (NULL == (sessp = arrlist_s_list_get_next_elem(ctx->sess_cache_arrlist))) {
        /* no cached session */
        return NULL;
    }

    sess = *sessp;

    arrlist_s_list_free_elem(ctx->sess_cache_arrlist, sessp);

    return sess;
}

int ossl_local_init(void)
{
    int err;

    if (NULL == (s_ossl_ctx_idlist = idlist_create_list("openssl ctx id list"))) {
        err = ERR_GET_LAST_ERR();
        goto ERR_1;
    }

    if (NULL == (s_ossl_ctx_idtable = idtable_create_table("openssl ctx id table",
        (lune_idtable_free_func_t)ossl_free_ctx, IDTABLE_MIN_TABLE_SIZE))) {
        err = ERR_GET_LAST_ERR();
        goto ERR_2;
    }

    if (NULL == (g_ossl_send_buf = lune_malloc_mt(OSSL_MAX_SEND_BUF_SIZE))) {
        err = ERR_GET_LAST_ERR();
        goto ERR_3;
    }

    g_ossl_send_len = 0;

    return 0;

ERR_3:
    lune_assert(!idtable_delete_table(s_ossl_ctx_idtable));
    s_ossl_ctx_idtable = NULL;

ERR_2:
    lune_assert(!idlist_delete_list(s_ossl_ctx_idlist));
    s_ossl_ctx_idlist = NULL;

ERR_1:
    return err;
}

void ossl_local_fini(void)
{
    lune_free_mt(g_ossl_send_buf);
    g_ossl_send_buf = NULL;

    lune_assert(!lune_idtable_delete_table(s_ossl_ctx_idtable));
    s_ossl_ctx_idtable = NULL;

    lune_assert(!idlist_delete_list(s_ossl_ctx_idlist));
    s_ossl_ctx_idlist = NULL;

    g_ossl_send_len = 0;
}

int ossl_init(void)
{
    SSL_load_error_strings();
    (void)OpenSSL_add_ssl_algorithms();
    return 0;
}

void ossl_fini(void)
{
    if (ossl_method != NULL) {
        BIO_meth_free(ossl_method);
        ossl_method = NULL;
    }

    EVP_cleanup();
}
