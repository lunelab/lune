/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2024 Lune Reseau, Inc.
 */

#ifndef __OSSL_H__
#define __OSSL_H__

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include "lune/err.h"
#include "lune/mem.h"
#include "lune/ssl.h"

#define OSSL_IS_INIT_FINISHED(ossl_ssl)         SSL_is_init_finished(((ossl_ssl_t *)ossl_ssl)->ssl)
#define OSSL_CONNECT(ossl_ssl)                  SSL_connect(((ossl_ssl_t *)ossl_ssl)->ssl)
#define OSSL_ACCEPT(ossl_ssl)                   SSL_accept(((ossl_ssl_t *)ossl_ssl)->ssl)
#define OSSL_RECV(ossl_ssl, buf, len)           \
    SSL_read(((ossl_ssl_t *)ossl_ssl)->ssl, (void *)buf, (int)len)
#define OSSL_IS_RECV_DONE()             (!!(0 == g_ossl_recv_left_len))
#define OSSL_SEND(ossl_ssl, buf, len)           \
    SSL_write(((ossl_ssl_t *)ossl_ssl)->ssl, (const void *)buf, (int)len)
#define OSSL_CLOSE(ossl_ssl)                    SSL_shutdown(((ossl_ssl_t *)ossl_ssl)->ssl)
#define OSSL_IS_SESS_CACHE_SET(ossl_ssl)        (NULL != ((ossl_ssl_t *)ossl_ssl)->ctx->sess_cache_arrlist)

#define OSSL_IS_QUIET_CLOSE(ossl_ssl)           SSL_get_quiet_shutdown(((ossl_ssl_t *)ossl_ssl)->ssl)
#define OSSL_SET_QUIET_CLOSE(ossl_ssl)          SSL_set_quiet_shutdown(((ossl_ssl_t *)ossl_ssl)->ssl, 1)
#define OSSL_SET_NORMAL_CLOSE(ossl_ssl)         SSL_set_quiet_shutdown(((ossl_ssl_t *)ossl_ssl)->ssl, 0)

#define OSSL_CTX_IS_QUIET_CLOSE(ossl_ctx)       SSL_CTX_get_quiet_shutdown(((ossl_ctx_t *)ossl_ctx)->ctx)
#define OSSL_CTX_SET_QUIET_CLOSE(ossl_ctx)      SSL_CTX_set_quiet_shutdown(((ossl_ctx_t *)ossl_ctx)->ctx, 1)
#define OSSL_CTX_SET_NORMAL_CLOSE(ossl_ctx)     SSL_CTX_set_quiet_shutdown(((ossl_ctx_t *)ossl_ctx)->ctx, 0)

#define OSSL_GET_SEND_BUF()                     (g_ossl_send_buf)
#define OSSL_GET_SEND_BUF_LEN()                 (g_ossl_send_len)
#define OSSL_CLEAR_SEND_BUF()                   do { g_ossl_send_len = 0; } while (0)

extern __thread unsigned int g_ossl_recv_left_len;

extern __thread unsigned char *g_ossl_send_buf;
extern __thread unsigned int g_ossl_send_len;

typedef enum _ossl_status {
    OSSL_STATUS_OK = 0,
    OSSL_STATUS_WANT_IO,
    OSSL_STATUS_SHUTDOWN,
    OSSL_STATUS_FAIL,
} ossl_status_en;

typedef struct _ossl_ctx {
    unsigned int id;
    unsigned int ref_cnt;
#define OSSL_CTX_FLAG_ON(ctx, flag)                 \
    (((struct _ossl_ctx *)(ctx))->flags & (flag))
#define OSSL_CTX_SET_FLAG(ctx, flag)                \
    do { ((struct _ossl_ctx *)(ctx))->flags |= (flag); } while (0)
#define OSSL_CTX_CLEAR_FLAG(ctx, flag)              \
    do { ((struct _ossl_ctx *)(ctx))->flags &= (~flag); } while (0)
#define OSSL_CTX_CLIENT_FLAG                        0x00000001
#define OSSL_CTX_IS_CLIENT(ctx)                     \
    OSSL_CTX_FLAG_ON(ctx, OSSL_CTX_CLIENT_FLAG)
#define OSSL_CTX_SET_CLIENT(ctx)                    \
    OSSL_CTX_SET_FLAG(ctx, OSSL_CTX_CLIENT_FLAG)
#define OSSL_CTX_SET_SERVER(ctx)                    \
    OSSL_CTX_CLEAR_FLAG(ctx, OSSL_CTX_CLIENT_FLAG)
#define OSSL_CTX_CERT_FLAG                          0x00000002
#define OSSL_CTX_IS_CERT_SET(ctx)                   \
    OSSL_CTX_FLAG_ON(ctx, OSSL_CTX_CERT_FLAG)
#define OSSL_CTX_SET_CERT(ctx)                      \
    OSSL_CTX_SET_FLAG(ctx, OSSL_CTX_CERT_FLAG)
#define SSL_CLEAR_CERT(ctx)                         \
    OSSL_CTX_CLEAR_FLAG(ctx, OSSL_CTX_CERT_FLAG)
    unsigned int flags;
    unsigned int rsvd;
    SSL_CTX *ctx;
    /* client only, cache session when LUNE_SSL_SESS_CACHE_CLIENT is set */
    void *sess_cache_arrlist;
} ossl_ctx_t;

#define OSSL_IS_CLIENT(ossl_ssl)                    \
    OSSL_CTX_IS_CLIENT(((ossl_ssl_t *)ossl_ssl)->ctx)

typedef struct _ossl_ssl {
    SSL *ssl;
    SSL_SESSION *sess;
    BIO *bio;
    ossl_ctx_t *ctx;
    /* flags read & write on np */
#define OSSL_FLAG_ON(ssl, flag)                     \
    (((struct _ossl_ssl *)(ssl))->flags & (flag))
#define OSSL_SET_FLAG(ssl, flag)                    \
    do { ((struct _ossl_ssl *)(ssl))->flags |= (flag); } while (0)
#define OSSL_CLEAR_FLAG(ssl, flag)                  \
    do { ((struct _ossl_ssl *)(ssl))->flags &= (~flag); } while (0)
#define OSSL_FLAG_DELETE                            0x00000001
#define OSSL_DELETE_ON(ssl)                         \
    OSSL_FLAG_ON(ssl, OSSL_FLAG_DELETE)
#define OSSL_DELETE_SET_ON(ssl)                     \
    OSSL_SET_FLAG(ssl, OSSL_FLAG_DELETE)
#define OSSL_DELETE_SET_OFF(ssl)                    \
    OSSL_CLEAR_FLAG(ssl, OSSL_FLAG_DELETE)
#define OSSL_FLAG_SYNC_SEND                         0x00000002
#define OSSL_SYNC_SEND_ON(ssl)                      \
    OSSL_FLAG_ON(ssl, OSSL_FLAG_SYNC_SEND)
#define OSSL_SYNC_SEND_SET_ON(ssl)                  \
    OSSL_SET_FLAG(ssl, OSSL_FLAG_SYNC_SEND)
#define OSSL_SYNC_SEND_SET_OFF(ssl)                 \
    OSSL_CLEAR_FLAG(ssl, OSSL_FLAG_SYNC_SEND)
    unsigned int flags;
    /* flags write on CP, read on CP & NP */
#define OSSL_CP_FLAG_ON(ssl, cp_flag)               \
    (((struct _ossl_ssl *)(ssl))->cp_flags & (cp_flag))
#define OSSL_SET_CP_FLAG(ssl, cp_flag)              \
    do { ((struct _ossl_ssl *)(ssl))->cp_flags =    \
        (((struct _ossl_ssl *)(ssl))->cp_flags | (cp_flag)); } while (0)
#define OSSL_CLEAR_CP_FLAG(ssl, cp_flag)            \
    do { ((struct _ossl_ssl *)(ssl))->cp_flags =    \
        (((struct _ossl_ssl *)(ssl))->cp_flags & (~cp_flag)); } while (0)
#define OSSL_FLAG_ASYNC_SEND                        0x00000001
#define OSSL_ASYNC_SEND_ON(ssl)                     \
    OSSL_CP_FLAG_ON(ssl, OSSL_FLAG_ASYNC_SEND)
#define OSSL_ASYNC_SEND_SET_ON(ssl)                 \
    OSSL_SET_CP_FLAG(ssl, OSSL_FLAG_ASYNC_SEND)
#define OSSL_ASYNC_SEND_SET_OFF(ssl)                \
    OSSL_CLEAR_CP_FLAG(ssl, OSSL_FLAG_ASYNC_SEND)
    unsigned int cp_flags;
    int ref_cnt;
} ossl_ssl_t;

static inline ossl_status_en ossl_get_status(ossl_ssl_t *ssl, int *ret)
{
    *ret = SSL_get_error(ssl->ssl, *ret);
    switch (*ret) {
    case SSL_ERROR_NONE:
        return OSSL_STATUS_OK;
    case SSL_ERROR_WANT_WRITE:
    case SSL_ERROR_WANT_READ:
        return OSSL_STATUS_WANT_IO;
    case SSL_ERROR_ZERO_RETURN:
        return OSSL_STATUS_SHUTDOWN;
    case SSL_ERROR_SYSCALL:
    default:
        return OSSL_STATUS_FAIL;
    }
}

static inline void ossl_ctx_first_hold(ossl_ctx_t *ctx)
{
#ifdef LUNE_DEBUG
    lune_assert(0 == ctx->ref_cnt);
#endif
    ++ctx->ref_cnt;
}

static inline void ossl_ctx_hold(ossl_ctx_t *ctx)
{
#ifdef LUNE_DEBUG
    lune_assert(ctx->ref_cnt > 0);
#endif
    ++ctx->ref_cnt;
}

static inline void ossl_ctx_put(ossl_ctx_t *ctx)
{
#ifdef LUNE_DEBUG
    lune_assert(ctx->ref_cnt > 0);
    lune_assert(NULL != ctx->ctx);
#endif
    if (0 == --ctx->ref_cnt) {
        /* free openssl ctx */
        lune_assert(LUNE_INVALID_ID == ctx->id);
        SSL_CTX_free(ctx->ctx);
        ctx->ctx = NULL;
        lune_free(ctx);
    }
}

void ossl_set_recv_pkt(const unsigned char *buf, unsigned int len);

unsigned int ossl_create_ctx(lune_ssl_version_en ver, lune_ssl_type_en type);
int ossl_delete_ctx(unsigned int id);
ossl_ctx_t *ossl_get_ctx(unsigned int id);
int ossl_load_certificate(ossl_ctx_t *ctx, const char *cert_file, const char *priv_key);

int ossl_get_sess_cache_mode(ossl_ctx_t *ctx, lune_ssl_sess_cache_mode_en *mode);

int ossl_set_ciphers(ossl_ctx_t *ctx, lune_ssl_cipher_en *ciphers_array, unsigned int ciphers_num);
int ossl_set_sess_cache_mode(ossl_ctx_t *ctx, lune_ssl_sess_cache_mode_en mode);

ossl_ssl_t *ossl_create_ssl(ossl_ctx_t *ctx);
void ossl_delete_ssl(ossl_ssl_t *ssl);

int ossl_async_handle_recv_pkt(ossl_ssl_t *ssl,
    void *sk, const unsigned char *buf, unsigned int len, unsigned int cp_idx);
int ossl_async_handle_send_pkt(ossl_ssl_t *ssl,
    void *sk, const unsigned char *buf, unsigned int len, unsigned int cp_idx);
int ossl_async_close_socket(ossl_ssl_t *ssl, void *sk, unsigned int cp_idx, unsigned int close_type);

int ossl_handle_coproc_req(const unsigned char *req, unsigned int req_len);
int ossl_handle_coproc_resp(const unsigned char *resp, unsigned int resp_len);

const char *ossl_get_cipher_str(lune_ssl_cipher_en cipher);

void ossl_save_session(ossl_ssl_t *ossl_ssl);
void ossl_unsave_session(ossl_ssl_t *ossl_ssl);

int ossl_local_init(void);
void ossl_local_fini(void);

int ossl_init(void);
void ossl_fini(void);

#endif