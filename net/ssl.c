/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2024 Lune Reseau, Inc.
 */

#include "lune/ip.h"
#include "lune/list.h"
#include "lune/log.h"
#include "lune/net.h"
#include "lune/os/linux.h"
#include "lune/tcp.h"
#include "lune/time.h"

#include "kernel/sched.h"
#include "kernel/timer.h"
#include "net/ip.h"
#include "net/ossl.h"
#include "net/socket.h"
#include "net/ssl.h"
#include "net/tcp.h"
#include "rt/core.h"

#define SSL_SEND_ORIG_PKT_MAX_SIZE          (2048)

/* Ratio: SSL encrypted data size / SSL original data size */
#define SSL_SEND_ENCRYPTED_DATA_RATIO       (2)
#define SSL_SEND_MIN_DATA_ROOM              (200)

static __thread lune_tcp_socket_callback_t s_ssl_tcp_socket_cb;

/*
    remove ssl socket on sync mode or async mode when there is no asynchronous
    request in the queue to CP
*/
static inline void ssl_teardown_socket(ssl_pcb_t *pcb)
{
    int err;

    lune_assert(0 == pcb->cp_send_len);

    if (OSSL_IS_SESS_CACHE_SET(pcb->ossl_ssl)) {
        /* don't cache the session when something goes wrong with it */
        ossl_unsave_session(pcb->ossl_ssl);
    }

    if (likely(!SOCKET_IS_CLOSED(pcb->tcp_sk))) {
        if (TCP_CLOSE_TYPE_NORMAL == TCP_GET_CLOSE_TYPE(pcb->tcp_pcb)) {
            TCP_SET_RST_CLOSE(pcb->tcp_pcb);
        }

        SOCKET_PUSH_CB_SK(pcb->tcp_sk);
        /* close tcp socket */
        if (0 != (err = lune_close_in_cb())) {
            lune_log(LUNE_INFO, "failed to close ssl connection %s: %s",
                tcp_print_pcb_4tuple(pcb->tcp_pcb),
                ERR_GET_ERR_STR(err));
        }
        SOCKET_POP_CB_SK();
    } else {
        /* error occurs while receiving packet at half-close state */
    }
}

static inline socket_t *ssl_create_passive_socket(socket_t *listen_sk, socket_x_t *tcp_sk)
{
    socket_t *sk;
    ssl_pcb_t *pcb;
    ssl_listen_pcb_t *listen_pcb = &listen_sk->pcb.ssl_listen;

    lune_assert(NULL != listen_sk);
    lune_assert(NULL != tcp_sk);

    if (NULL == (sk = socket_create(LUNE_SOCKET_SSL))) {
        goto ERR_1;
    }

    pcb = &sk->pcb.ssl;
    pcb->tcp_sk = tcp_sk;
    pcb->tcp_pcb = &pcb->tcp_sk->pcb.tcp;
    socket_hold(pcb->tcp_sk);
    pcb->tcp_ops = socket_get_socket_ops(LUNE_SOCKET_TCP);
    /* make sure data is all (not partial) transmitted by tcp layer */
    TCP_ALL_OR_NONE_XMIT_TURN_ON(pcb->tcp_pcb);
    pcb->ifp = pcb->tcp_pcb->ifp;

    if (NULL == (pcb->ossl_ssl = ossl_create_ssl(listen_pcb->ossl_ctx))) {
        goto ERR_2;
    }

    if (SSL_CLOSE_TYPE_RST == SSL_GET_CLOSE_TYPE(listen_pcb)) {
        SSL_SET_RST_CLOSE(pcb);
        TCP_SET_RST_CLOSE(pcb->tcp_pcb);
        /* pcb->ossl_ssl inherits quiet mode from listen_pcb->ossl_ctx, no need to set it explicitly */
    } else if (SSL_CLOSE_TYPE_NORMAL == SSL_GET_CLOSE_TYPE(listen_pcb)) {
        SSL_SET_NORMAL_CLOSE(pcb);
        TCP_SET_NORMAL_CLOSE(pcb->tcp_pcb);
        /* pcb->ossl_ssl inherits normal mode from listen_pcb->ossl_ctx, no need to set it explicitly */
    } else {
#ifdef LUNE_DEBUG
        lune_assert(SSL_CLOSE_TYPE_QUIET == SSL_GET_CLOSE_TYPE(listen_pcb));
#endif
        SSL_SET_QUIET_CLOSE(pcb);
        TCP_SET_QUIET_CLOSE(pcb->tcp_pcb);
        /* pcb->ossl_ssl inherits quiet mode from listen_pcb->ossl_ctx, no need to set it explicitly */
    }

    memcpy(&pcb->cb, &listen_pcb->cb, sizeof(lune_ssl_socket_callback_t));
    pcb->err_code = LUNE_ERR_NO_ERR;

    return sk;

ERR_2:
    socket_put(pcb->tcp_sk);
    lune_assert(!socket_close(sk));

ERR_1:
    return NULL;
}

static int ssl_sync_send(socket_t *sk, const unsigned char *buf, unsigned int len)
{
    ssl_pcb_t *pcb = &sk->pcb.ssl;
    int sent_len;

    if ((int)len != (sent_len = pcb->tcp_ops->send((socket_t *)pcb->tcp_sk, buf, len))) {
        lune_assert(sent_len <= 0);
    }

    return sent_len;
}

static void ssl_tcp_socket_connect(socket_t *sk)
{
    ssl_pcb_t *pcb = &sk->pcb.ssl;
    int err, sent_len;
    ossl_ssl_t *ssl = pcb->ossl_ssl;
    ossl_status_en status;

    err = OSSL_CONNECT(ssl);
    status = ossl_get_status(ssl, &err);
    switch (status) {
    case OSSL_STATUS_OK:
    case OSSL_STATUS_WANT_IO:
        break;
    default:
        lune_log(LUNE_INFO, "failed to establish ssl connection %s due to SSL error %d",
            tcp_print_pcb_4tuple(pcb->tcp_pcb),
            err);
        pcb->err_code = ERR_SET_ERR(LUNE_ERR_SSL_INTERNAL);
        ssl_teardown_socket(pcb);
        return;
    }

    if (likely(OSSL_SYNC_SEND_ON(ssl))) {
        /* the first handshake from client is ALWAYS assembled on sync mode */
        OSSL_SYNC_SEND_SET_OFF(ssl);
        if ((int)OSSL_GET_SEND_BUF_LEN() != (sent_len = ssl_sync_send(sk,
            OSSL_GET_SEND_BUF(), OSSL_GET_SEND_BUF_LEN()))) {
            if (likely(sent_len < 0)) {
                lune_log(LUNE_INFO, "failed to establish ssl connection %s: %s",
                    tcp_print_pcb_4tuple(pcb->tcp_pcb),
                    ERR_GET_ERR_STR(sent_len));
            } else {
                /* very unlikely, fail to send the very first data on underlying tcp connection */
                lune_assert(0 == sent_len);
                sent_len = ERR_SET_ERR(LUNE_ERR_TCP_CWND_FULL);
                lune_log(LUNE_INFO, "failed to establish ssl connection %s: "
                    "ssl first handshake not sent due to %s",
                    tcp_print_pcb_4tuple(pcb->tcp_pcb),
                    ERR_GET_ERR_STR(sent_len));
            }
            pcb->err_code = sent_len;
            ssl_teardown_socket(pcb);
            OSSL_CLEAR_SEND_BUF();
            return;
        }

        OSSL_CLEAR_SEND_BUF();
    }
}

static void ssl_tcp_socket_accept(unsigned int socket_id __attribute__((unused)), 
    lune_socket_addr_t *addr __attribute__((unused)), void **pdata)
{
    socket_t *sk, *listen_sk = *pdata;
    socket_x_t *tcp_sk;
    ssl_pcb_t *pcb;
    int err;

    lune_assert(NULL != listen_sk);
    lune_assert(NULL != (tcp_sk = (socket_x_t *)SOCKET_GET_CB_SK()));

    if (NULL == (sk = ssl_create_passive_socket(listen_sk, tcp_sk))) {
        tcp_pcb_t *tcp_pcb = &tcp_sk->pcb.tcp;

        lune_log(LUNE_INFO, "failed to create ssl connection on tcp connection %s: %s",
            tcp_print_pcb_4tuple(tcp_pcb),
            ERR_GET_LAST_ERR_STR());

        TCP_SET_RST_CLOSE(tcp_pcb);
        if (0 != (err = lune_close_in_cb())) {
            lune_log(LUNE_INFO, "failed to close ssl connection %s: %s",
                tcp_print_pcb_4tuple(tcp_pcb),
                ERR_GET_ERR_STR(err));
        }

        return;
    }

    pcb = &sk->pcb.ssl;

    /*
        closing ssl listening socket at current stage has no impact on accepted socket,
        as tcp connection has already been established.
    */
    SSL_SET_PASSIVE(pcb);

    *pdata = sk;
    socket_hold(sk);
}

static void ssl_sync_handle_conn_established(socket_t *sk, ossl_ssl_t *ssl, int err)
{
    ossl_status_en status;
    ssl_pcb_t *pcb = &sk->pcb.ssl;
    int sent_len;

    if (unlikely(SOCKET_IS_CLOSED(sk)
        || NULL == pcb->tcp_sk
        || SOCKET_IS_CLOSED(pcb->tcp_sk)
        || pcb->ossl_ssl != ssl)) {
        lune_log(LUNE_INFO, "ssl connection %d already closed during establishment", SOCKET_GET_ID(sk));
        ERR_SET_ERR(LUNE_ERR_SSL_INTERNAL);
        return;
    }

#ifdef LUNE_DEBUG
    lune_assert(!SSL_IS_ESTABLISHED(pcb));
#endif

    status = ossl_get_status(ssl, &err);
    switch (status) {
    case OSSL_STATUS_OK:
    case OSSL_STATUS_WANT_IO:
        break;
    case OSSL_STATUS_SHUTDOWN:
        /*
            very unlikely, received ssl close_notify message during connection establishment.
            inform application, delete ssl and wait for the peer to close tcp connection
        */
        lune_assert(0 == pcb->cp_send_len);

        if (NULL != pcb->cb.closewait) {
            SOCKET_PUSH_CB_SK(sk);
            pcb->cb.closewait(pcb->cb.data);
            SOCKET_POP_CB_SK();
        }

        if (NULL != pcb->ossl_ssl) {
            /* socket not close in callback closewait(), wait for the peer to close tcp connection */
            ossl_delete_ssl(pcb->ossl_ssl);
            pcb->ossl_ssl = NULL;
        }

        return;
    default:
        lune_log(LUNE_INFO, "failed to establish ssl connection %s due to SSL error %d",
            tcp_print_pcb_4tuple(pcb->tcp_pcb),
            err);
        pcb->err_code = ERR_SET_ERR(LUNE_ERR_SSL_INTERNAL);
        ssl_teardown_socket(pcb);
        return;
    }

    if (OSSL_SYNC_SEND_ON(ssl)) {
        OSSL_SYNC_SEND_SET_OFF(ssl);
        if ((int)OSSL_GET_SEND_BUF_LEN() != (sent_len = ssl_sync_send(sk,
            OSSL_GET_SEND_BUF(), OSSL_GET_SEND_BUF_LEN()))) {
            if (likely(sent_len < 0)) {
                lune_log(LUNE_INFO, "failed to establish ssl connection %s: %s",
                    tcp_print_pcb_4tuple(pcb->tcp_pcb),
                    ERR_GET_ERR_STR(sent_len));
            } else {
                lune_assert(0 == sent_len);
                sent_len = ERR_SET_ERR(LUNE_ERR_TCP_CWND_FULL);
                lune_log(LUNE_INFO, "failed to establish ssl connection %s: "
                    "ssl handshake not sent due to %s",
                    tcp_print_pcb_4tuple(pcb->tcp_pcb),
                    ERR_GET_ERR_STR(sent_len));
            }
            pcb->err_code = sent_len;
            ssl_teardown_socket(pcb);
            OSSL_CLEAR_SEND_BUF();
            return;
        }

        OSSL_CLEAR_SEND_BUF();
    }

    if (OSSL_IS_INIT_FINISHED(ssl)) {
        /* ssl connection has been established */
        SSL_SET_ESTABLISHED(pcb);
        SSL_CLEAR_ATTEMPTING(pcb);

        if (likely(NULL != pcb->ifp)) {
            NET_IF_SSL_INC_ESTABLISHED_CONN(pcb->ifp);
            NET_IF_SSL_INC_CONCURRENT_CONN(pcb->ifp);
        }

        if (OSSL_IS_CLIENT(ssl)) {
            if (OSSL_IS_SESS_CACHE_SET(ssl)) {
                /*
                    save session now (connection established)
                    and cache later (connection closed)
                */
                ossl_save_session(ssl);
            }

            if (likely(NULL != pcb->cb.connect)) {
                SOCKET_PUSH_CB_SK(sk);
                pcb->cb.connect(pcb->cb.data);
                SOCKET_POP_CB_SK();
            }
        } else {
            if (likely(NULL != pcb->cb.accept)) {
                lune_socket_addr_t addr;
                LUNE_IP_CPY(&addr.addr, &pcb->tcp_pcb->dst_ip);
                addr.port = pcb->tcp_pcb->dst_port;
                SOCKET_PUSH_CB_SK(sk);
                pcb->cb.accept(SOCKET_GET_ID(sk), &addr, &pcb->cb.data);
                SOCKET_POP_CB_SK();
            }
        }
    }
}

int ssl_async_handle_conn_established(socket_t *sk, ossl_ssl_t *ssl)
{
    ssl_pcb_t *pcb = &sk->pcb.ssl;

    if (unlikely(SOCKET_IS_CLOSED(sk)
        || NULL == pcb->tcp_sk
        || SOCKET_IS_CLOSED(pcb->tcp_sk)
        || pcb->ossl_ssl != ssl)) {
        lune_log(LUNE_INFO, "ssl connection %d already closed while handling"
            " asynchronous response", SOCKET_GET_ID(sk));
        return ERR_SET_ERR(LUNE_ERR_SSL_INTERNAL);
    }

    lune_assert(!SSL_IS_ESTABLISHED(pcb));

    /* ssl connection has been established */
    SSL_SET_ESTABLISHED(pcb);
    SSL_CLEAR_ATTEMPTING(pcb);

    if (likely(NULL != pcb->ifp)) {
        NET_IF_SSL_INC_ESTABLISHED_CONN(pcb->ifp);
        NET_IF_SSL_INC_CONCURRENT_CONN(pcb->ifp);
    }

    if (OSSL_IS_CLIENT(ssl)) {
        if (OSSL_IS_SESS_CACHE_SET(ssl)) {
            /*
                save session now (connection established)
                and cache later (connection closed)
            */
            ossl_save_session(ssl);
        }

        if (likely(NULL != pcb->cb.connect)) {
            SOCKET_PUSH_CB_SK(sk);
            pcb->cb.connect(pcb->cb.data);
            SOCKET_POP_CB_SK();
        }
    } else {
        if (likely(NULL != pcb->cb.accept)) {
            lune_socket_addr_t addr;
            LUNE_IP_CPY(&addr.addr, &pcb->tcp_pcb->dst_ip);
            addr.port = pcb->tcp_pcb->dst_port;
            SOCKET_PUSH_CB_SK(sk);
            pcb->cb.accept(SOCKET_GET_ID(sk), &addr, &pcb->cb.data);
            SOCKET_POP_CB_SK();
        }
    }

    return 0;
}

int ssl_async_recv(socket_t *sk,
    ossl_ssl_t *ssl, const unsigned char *buf, unsigned int len, int err)
{
    ssl_pcb_t *pcb = &sk->pcb.ssl;

    lune_assert(0 == err);
    lune_assert(len > 0 && len <= SSL_RECV_DECRYPTED_PKT_MAX_SIZE);

    if (unlikely(SOCKET_IS_CLOSED(sk)
        || NULL == pcb->tcp_sk
        || SOCKET_IS_CLOSED(pcb->tcp_sk)
        || pcb->ossl_ssl != ssl)) {
        lune_log(LUNE_INFO, "ssl connection %d already closed while handling"
            " asynchronous response", SOCKET_GET_ID(sk));
        return ERR_SET_ERR(LUNE_ERR_SSL_INTERNAL);
    }

    if (likely(NULL != pcb->ifp)) {
        NET_IF_SSL_ADD_DATA_DEC(pcb->ifp, len);
    }

    if (likely(NULL != pcb->cb.recv)) {
        SOCKET_PUSH_CB_SK(sk);
        pcb->cb.recv(pcb->cb.data, (const unsigned char *)buf, len);
        SOCKET_POP_CB_SK();
    }

    return 0;
}

static int ssl_sync_recv(socket_t *sk,
    ossl_ssl_t *ssl, const unsigned char *buf, unsigned int len, int err)
{
    ossl_status_en status;
    ssl_pcb_t *pcb = &sk->pcb.ssl;

#ifdef LUNE_DEBUG
    lune_assert(!SOCKET_IS_CLOSED(sk));
    lune_assert(SSL_IS_ESTABLISHED(pcb));
    lune_assert(!SOCKET_IS_CLOSED(pcb->tcp_sk));
#endif

    if (err <= 0) {
        status = ossl_get_status(ssl, &err);
        switch (status) {
        case OSSL_STATUS_WANT_IO:
            break;
        case OSSL_STATUS_SHUTDOWN:
            lune_assert(0 == pcb->cp_send_len);

            if (NULL != pcb->cb.closewait) {
                SOCKET_PUSH_CB_SK(sk);
                pcb->cb.closewait(pcb->cb.data);
                SOCKET_POP_CB_SK();
            }

            if (NULL != pcb->ossl_ssl) {
                /* socket not close in callback closewait(), wait for the peer to close tcp connection */
                if (likely(NULL != pcb->ifp)) {
                    NET_IF_SSL_INC_CLOSED_CONN(pcb->ifp);
                    NET_IF_SSL_DEC_CONCURRENT_CONN(pcb->ifp);
                }

                ossl_delete_ssl(pcb->ossl_ssl);
                pcb->ossl_ssl = NULL;
            }

            return 0;
        default:
            lune_log(LUNE_INFO, "failed to decrypt ssl data due to SSL error %d"
                " on ssl connection %s",
                err,
                tcp_print_pcb_4tuple(pcb->tcp_pcb));
            pcb->err_code = ERR_SET_ERR(LUNE_ERR_SSL_INTERNAL);
            ssl_teardown_socket(pcb);
            return ERR_GET_LAST_ERR();
        }
    }

    if (0 == len) {
        return 0;
    }

    lune_assert(len > 0 && len <= SSL_RECV_DECRYPTED_PKT_MAX_SIZE);

    if (likely(NULL != pcb->ifp)) {
        NET_IF_SSL_ADD_DATA_DEC(pcb->ifp, len);
    }

    if (likely(NULL != pcb->cb.recv)) {
        SOCKET_PUSH_CB_SK(sk);
        pcb->cb.recv(pcb->cb.data, (const unsigned char *)buf, len);
        SOCKET_POP_CB_SK();
    }

    return 0;
}

static void ssl_tcp_socket_recv(socket_t *sk, const unsigned char *buf, unsigned int len)
{
    ssl_pcb_t *pcb = &sk->pcb.ssl;
    int err, recv_len, dec_len;
    void *ssl = pcb->ossl_ssl;
    unsigned char *recv_buf;
    unsigned char dec_buf[SSL_RECV_DECRYPTED_PKT_MAX_SIZE];
    ossl_status_en status;

    if (unlikely(NULL == ssl)) {
        /* drop packet as ssl already deleted */
        return;
    }

    if (CORE_IS_CP_BOUND()) {
        if (CORE_NP_MAX_BOUND_CP_NUM == pcb->cp_idx
            || !CORE_NP_IS_CP_ACTIVE(pcb->cp_idx)) {
            lune_assert(CORE_NP_MAX_BOUND_CP_NUM != (pcb->cp_idx = core_get_next_bound_cp_idx()));
        } else {
            /*
                ssl socket already bound to certain active CP
            */
        }

        goto ASYNC_RECV;
    }

    /* synchronous receive */

    ossl_set_recv_pkt(buf, len);

    if (!OSSL_IS_INIT_FINISHED(ssl)) {
        /* connection not established yet */
        if (OSSL_IS_CLIENT(ssl)) {
            err = OSSL_CONNECT(ssl);
        } else {
            err = OSSL_ACCEPT(ssl);
        }

        ssl_sync_handle_conn_established(sk, ssl, err);
        return;
    }

DECODE:
    recv_buf = dec_buf;
    dec_len = 0;
    do {
        recv_len = OSSL_RECV(ssl, recv_buf, SSL_RECV_DECRYPTED_PKT_MAX_SIZE - dec_len);
#ifdef LUNE_DEBUG
        lune_assert(!OSSL_SYNC_SEND_ON(ssl));
#endif
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
            break;
        case OSSL_STATUS_SHUTDOWN:
            lune_assert(SSL_IS_ESTABLISHED(pcb));
            lune_assert(0 == pcb->cp_send_len);

            if (NULL != pcb->cb.closewait) {
                SOCKET_PUSH_CB_SK(sk);
                pcb->cb.closewait(pcb->cb.data);
                SOCKET_POP_CB_SK();
            }

            if (NULL != pcb->ossl_ssl) {
                /* socket not close in callback closewait(), wait for the peer to close tcp connection */
                if (likely(NULL != pcb->ifp)) {
                    NET_IF_SSL_INC_CLOSED_CONN(pcb->ifp);
                    NET_IF_SSL_DEC_CONCURRENT_CONN(pcb->ifp);
                }

                ossl_delete_ssl(pcb->ossl_ssl);
                pcb->ossl_ssl = NULL;
            }

            break;
        default:
            lune_assert(0);
            /* fall through */
        case OSSL_STATUS_FAIL:
            lune_log(LUNE_INFO, "failed to decrypt ssl data due to SSL error %d"
                " on ssl connection %s",
                err,
                tcp_print_pcb_4tuple(pcb->tcp_pcb));
            pcb->err_code = ERR_SET_ERR(LUNE_ERR_SSL_INTERNAL);
            ssl_teardown_socket(pcb);
            break;
        }

        return;
    }

    if (ssl_sync_recv(sk, ssl, dec_buf, dec_len, recv_len)) {
        return;
    }

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
        goto DECODE;
    }

    return;

ASYNC_RECV:
    if (0 == (err = ossl_async_handle_recv_pkt(ssl, sk, buf, len, pcb->cp_idx))) {
        /* async mode */
        socket_hold(sk);
        pcb->cp_req_cnt++;
        return;
    }

    /* queue full, close socket */
    lune_log_once(LUNE_INFO, "failed to handle received packet on async mode"
        " on ssl connection %s: %s",
        tcp_print_pcb_4tuple(pcb->tcp_pcb),
        ERR_GET_ERR_STR(err));
    pcb->err_code = err;
    if (pcb->cp_req_cnt > 0) {
        /* all asynchronous requests will be skipped and then socket will be closed */
        ossl_delete_ssl(pcb->ossl_ssl);
        pcb->ossl_ssl = NULL;
    } else {
        ssl_teardown_socket(pcb);
    }
}

static void ssl_tcp_socket_closewait(socket_t *sk __attribute__((unused)))
{
    int err;
    ssl_pcb_t *pcb = &sk->pcb.ssl;

    if (pcb->cp_req_cnt > 0) {
        /* hold off socket closure until the queue is emptied */
        SSL_SET_TCP_CLWAIT(pcb);
        return;
    }

    /* close tcp socket */
    if (0 != (err = lune_close_in_cb())) {
        lune_log(LUNE_INFO, "failed to close tcp socket at %s state"
            " on ssl connection %s: %s",
            TCP_GET_STATE_STR(pcb->tcp_pcb->state),
            tcp_print_pcb_4tuple(pcb->tcp_pcb),
            ERR_GET_ERR_STR(err));
    }
}

static void ssl_tcp_socket_error(socket_t *sk, int err_code)
{
    ssl_pcb_t *pcb = &sk->pcb.ssl;

    lune_log(LUNE_DBG, "tcp socket error occurred on ssl connection %s: %s",
        tcp_print_pcb_4tuple(pcb->tcp_pcb),
        ERR_GET_ERR_STR(err_code));

    if (NULL != pcb->ossl_ssl) {
        if (SSL_IS_ATTEMPTING(pcb)) {
            if (likely(NULL != pcb->ifp)) {
                NET_IF_SSL_INC_ABORTED_CONN(pcb->ifp);
            }
        } else if (SSL_IS_ESTABLISHED(pcb)) {
            if (likely(NULL != pcb->ifp)) {
                NET_IF_SSL_INC_FAILED_CONN(pcb->ifp);
                NET_IF_SSL_DEC_CONCURRENT_CONN(pcb->ifp);
            }
        } else {
            /* passive connection still in the course of ssl establishment */
            lune_assert(SSL_IS_PASSIVE_CONN(pcb));
        }

        lune_assert(0 == pcb->cp_send_len);

        ossl_delete_ssl(pcb->ossl_ssl);
        pcb->ossl_ssl = NULL;
    } else {
        if (SSL_IS_ATTEMPTING(pcb)) {
            /* ssl connection was closed before establishment */
            NET_IF_SSL_INC_ABORTED_CONN(pcb->ifp);
        }
    }

    if (!SOCKET_IS_CLOSED(sk)) {
        /* close socket so it's not accessible in callback error() */
        lune_assert(!socket_close(sk));
    }

    if (SSL_IS_ATTEMPTING(pcb) || SSL_IS_ESTABLISHED(pcb)) {
        if (NULL != pcb->cb.error) {
            SOCKET_PUSH_CB_SK(sk);
            pcb->cb.error(pcb->cb.data, err_code);
            SOCKET_POP_CB_SK();
        }
    }

    socket_put(pcb->tcp_sk);
    pcb->tcp_sk = NULL;
    pcb->tcp_pcb = NULL;
    pcb->ifp = NULL;

    socket_put(sk);
}

static void ssl_tcp_socket_close(socket_t *sk, unsigned int close_type)
{
    ssl_pcb_t *pcb = &sk->pcb.ssl;

    if (NULL != pcb->ossl_ssl) {
        if (SSL_IS_ATTEMPTING(pcb)) {
            if (likely(NULL != pcb->ifp)) {
                NET_IF_SSL_INC_ABORTED_CONN(pcb->ifp);
            }
        } else if (SSL_IS_ESTABLISHED(pcb)) {
            if (likely(NULL != pcb->ifp)) {
                if (LUNE_ERR_NO_ERR != pcb->err_code) {
                    NET_IF_SSL_INC_FAILED_CONN(pcb->ifp);
                } else {
                    NET_IF_SSL_INC_CLOSED_CONN(pcb->ifp);
                }
                NET_IF_SSL_DEC_CONCURRENT_CONN(pcb->ifp);
            }
        } else {
            /*
                passive connection still in the course of ssl establishment
            */
            lune_assert(SSL_IS_PASSIVE_CONN(pcb));
        }

        ossl_delete_ssl(pcb->ossl_ssl);
        pcb->ossl_ssl = NULL;
    } else {
        if (SSL_IS_ATTEMPTING(pcb)) {
            /* ssl connection was closed before establishment */
            if (likely(NULL != pcb->ifp)) {
                NET_IF_SSL_INC_ABORTED_CONN(pcb->ifp);
            }
        }
    }

    if (!SOCKET_IS_CLOSED(sk)) {
        /* close socket so it's not accessible in callback error() / close() */
        lune_assert(!socket_close(sk));
    }

    if (SSL_IS_ATTEMPTING(pcb) || SSL_IS_ESTABLISHED(pcb)) {
        if (LUNE_ERR_NO_ERR != pcb->err_code) {
            /* ssl error */
            if (NULL != pcb->cb.error) {
                SOCKET_PUSH_CB_SK(sk);
                pcb->cb.error(pcb->cb.data, pcb->err_code);
                SOCKET_POP_CB_SK();
            }
            pcb->err_code = LUNE_ERR_NO_ERR;
        } else {
            if (likely(NULL != pcb->cb.close)) {
                SOCKET_PUSH_CB_SK(sk);
                pcb->cb.close(pcb->cb.data, close_type);
                SOCKET_POP_CB_SK();
            }
        }
    }

    socket_put(pcb->tcp_sk);
    pcb->tcp_sk = NULL;
    pcb->tcp_pcb = NULL;
    pcb->ifp = NULL;

    socket_put(sk);
}

/********** ssl socket **********/

static __thread lune_tcp_socket_callback_t s_ssl_tcp_socket_cb = {
    .connect = (lune_tcp_socket_connect_callback_func_t)ssl_tcp_socket_connect,
    .accept = NULL,
    .recv = (lune_tcp_socket_recv_callback_func_t)ssl_tcp_socket_recv,
    .closewait = (lune_tcp_socket_closewait_callback_func_t)ssl_tcp_socket_closewait,
    .error = (lune_tcp_socket_error_callback_func_t)ssl_tcp_socket_error,
    .close = (lune_tcp_socket_close_callback_func_t)ssl_tcp_socket_close,
    .data = NULL,
};

static int ssl_socket_create(socket_t *sk)
{
    ssl_pcb_t *pcb = &sk->pcb.ssl;

    pcb->tcp_sk = NULL;
    pcb->tcp_pcb = NULL;
    pcb->tcp_ops = socket_get_socket_ops(LUNE_SOCKET_TCP);
    pcb->ifp = NULL;
    pcb->ossl_ssl = NULL;
    memset(&pcb->cb, 0x00, sizeof(lune_ssl_socket_callback_t));
    pcb->err_code = LUNE_ERR_NO_ERR;
    pcb->flags = 0;
    pcb->cp_req_cnt = 0;
    pcb->cp_idx = CORE_NP_MAX_BOUND_CP_NUM;
    pcb->cp_send_len = 0;

    return 0;
}

static int ssl_socket_bind(socket_t *sk, const void *arg, unsigned int arg_len)
{
    ssl_pcb_t *pcb = &sk->pcb.ssl;
    int err;

    if (NULL != pcb->tcp_sk) {
        err = ERR_SET_ERR(LUNE_ERR_ALREADY_BOUND);
        goto ERR_1;
    }

    if (NULL == (pcb->tcp_sk = (socket_x_t *)socket_create(LUNE_SOCKET_TCP))) {
        err = ERR_GET_LAST_ERR();
        goto ERR_1;
    }

    socket_hold(pcb->tcp_sk);
    pcb->tcp_pcb = &pcb->tcp_sk->pcb.tcp;
    /* make sure data is all (not partial) transmitted by tcp layer */
    TCP_ALL_OR_NONE_XMIT_TURN_ON(pcb->tcp_pcb);

    switch (SSL_GET_CLOSE_TYPE(pcb)) {
    case SSL_CLOSE_TYPE_NORMAL:
        TCP_SET_NORMAL_CLOSE(pcb->tcp_pcb);
        break;
    case SSL_CLOSE_TYPE_RST:
        TCP_SET_RST_CLOSE(pcb->tcp_pcb);
        break;
    case SSL_CLOSE_TYPE_QUIET:
        TCP_SET_QUIET_CLOSE(pcb->tcp_pcb);
        break;
    default:
        err = ERR_SET_ERR(LUNE_ERR_SSL_INTERNAL);
        goto ERR_2;
    }

    if (0 != (err = pcb->tcp_ops->bind((socket_t *)pcb->tcp_sk, arg, arg_len))) {
        goto ERR_2;
    }

    pcb->ifp = pcb->tcp_pcb->ifp;
#ifdef LUNE_DEBUG
    lune_assert(NULL != pcb->ifp);
#endif

    return 0;

ERR_2:
    socket_put(pcb->tcp_sk);
    lune_assert(!socket_close(pcb->tcp_sk));
    pcb->tcp_sk = NULL;
    pcb->tcp_pcb = NULL;

ERR_1:
    return err;
}

static int ssl_socket_connect(socket_t *sk, const void *arg, unsigned int arg_len)
{
    ssl_pcb_t *pcb = &sk->pcb.ssl;
    int err;

    if (NULL == pcb->ossl_ssl) {
        return ERR_SET_ERR(LUNE_ERR_SSL_NOT_SET);
    }

    if (NULL == pcb->tcp_sk) {
        return ERR_SET_ERR(LUNE_ERR_NOT_BOUND);
    }

    if (unlikely(SSL_IS_ATTEMPTING(pcb))) {
        return ERR_SET_ERR(LUNE_ERR_SOCKET_CONNECTING);
    }

    if (unlikely(SSL_IS_ESTABLISHED(pcb))) {
        return ERR_SET_ERR(LUNE_ERR_SOCKET_ALREADY_CONNECTED);
    }

    s_ssl_tcp_socket_cb.data = sk;
    if (0 != (err = pcb->tcp_ops->set_opt((socket_t *)pcb->tcp_sk, LUNE_SOCKET_OPT_SET_CALLBACK,
        (const unsigned char *)&s_ssl_tcp_socket_cb, sizeof(s_ssl_tcp_socket_cb)))) {
        s_ssl_tcp_socket_cb.data = NULL;
        return err;
    }
    s_ssl_tcp_socket_cb.data = NULL;

    if (0 != (err = pcb->tcp_ops->connect((socket_t *)pcb->tcp_sk, arg, arg_len))) {
        return err;
    }

    SSL_SET_ATTEMPTING(pcb);
    if (likely(NULL != pcb->ifp)) {
        NET_IF_SSL_INC_ATTEMPTED_CONN(pcb->ifp);
    }

    socket_hold(sk);

    return 0;
}

static int ssl_socket_get_opt(socket_t *sk,
    lune_socket_opt_en opt, unsigned char *opt_val, unsigned int opt_len)
{
    ssl_pcb_t *pcb = &sk->pcb.ssl;

    switch (opt) {
    case LUNE_SOCKET_OPT_GET_SRC_IP_ID:
        if (unlikely(NULL == opt_val || opt_len != sizeof(unsigned int))) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        if (NULL == pcb->tcp_sk) {
            return ERR_SET_ERR(LUNE_ERR_NOT_BOUND);
        }

        if (NULL == pcb->tcp_pcb->ipp) {
            return ERR_SET_ERR(LUNE_ERR_NOT_BOUND);
        }

        *(unsigned int *)opt_val = IP_GET_ID(pcb->tcp_pcb->ipp);
        break;
    case LUNE_SOCKET_OPT_GET_TCP_MSS:
        if (unlikely(NULL == opt_val || opt_len != sizeof(unsigned short))) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        if (NULL == pcb->tcp_pcb) {
            return ERR_SET_ERR(LUNE_ERR_NOT_BOUND);
        }

        lune_assert(NULL != pcb->tcp_pcb->ipp);

        *(unsigned short *)opt_val = pcb->tcp_pcb->mss;
        break;
    default:
        return ERR_SET_ERR(LUNE_ERR_OPT_NOT_FOUND);
    }

    return 0;
}

static int ssl_socket_set_opt(socket_t *sk,
    lune_socket_opt_en opt, const unsigned char *opt_val, unsigned int opt_len)
{
    ssl_pcb_t *pcb = &sk->pcb.ssl;

    switch (opt) {
    case LUNE_SOCKET_OPT_SET_CALLBACK:
        if (NULL == opt_val
            || opt_len != sizeof(lune_ssl_socket_callback_t)) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        if (NULL != ((const lune_ssl_socket_callback_t *)opt_val)->accept) {
            lune_log(LUNE_INFO, "attempted to register accept event"
                " on ssl socket %d", SOCKET_GET_ID(sk));
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        memcpy(&pcb->cb, opt_val, sizeof(lune_ssl_socket_callback_t));
        break;
    case LUNE_SOCKET_OPT_CLEAR_CALLBACK:
        if (unlikely(NULL != opt_val || 0 != opt_len)) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        memset(&pcb->cb, 0x00, sizeof(lune_ssl_socket_callback_t));
        break;
    case LUNE_SOCKET_OPT_SET_NORMAL_CLOSE:
        if (unlikely(NULL != opt_val || 0 != opt_len)) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        if (NULL == pcb->ossl_ssl) {
            /*
                SSL has to be set before closure mode, or the mode will be overwritten
                with the one inherited from SSL set to the socket
            */
            return ERR_SET_ERR(LUNE_ERR_NOT_SET);
        }

        if (likely(SSL_GET_CLOSE_TYPE(pcb) != SSL_CLOSE_TYPE_NORMAL)) {
            SSL_SET_NORMAL_CLOSE(pcb);
            if (NULL != pcb->tcp_pcb) {
                TCP_SET_NORMAL_CLOSE(pcb->tcp_pcb);
            }
            OSSL_SET_NORMAL_CLOSE(pcb->ossl_ssl);
        } else {
            lune_log(LUNE_INFO, "normal closure already set on ssl socket %d",
                SOCKET_GET_ID(sk));
        }

        break;
    case LUNE_SOCKET_OPT_SET_RST_CLOSE:
        if (unlikely(NULL != opt_val || 0 != opt_len)) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        if (NULL == pcb->ossl_ssl) {
            /*
                SSL has to be set before closure mode, or the mode will be overwritten
                with the one inherited from SSL set to the socket
            */
            return ERR_SET_ERR(LUNE_ERR_NOT_SET);
        }

        if (likely(SSL_GET_CLOSE_TYPE(pcb) != SSL_CLOSE_TYPE_RST)) {
            SSL_SET_RST_CLOSE(pcb);
            if (NULL != pcb->tcp_pcb) {
                TCP_SET_RST_CLOSE(pcb->tcp_pcb);
            }
            OSSL_SET_QUIET_CLOSE(pcb->ossl_ssl);
        }

        break;
    case LUNE_SOCKET_OPT_SET_QUIET_CLOSE:
        if (unlikely(NULL != opt_val || 0 != opt_len)) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        if (NULL == pcb->ossl_ssl) {
            /*
                SSL has to be set before closure mode, or the mode will be overwritten
                with the one inherited from SSL set to the socket
            */
            return ERR_SET_ERR(LUNE_ERR_NOT_SET);
        }

        if (likely(SSL_GET_CLOSE_TYPE(pcb) != SSL_CLOSE_TYPE_QUIET)) {
            SSL_SET_QUIET_CLOSE(pcb);
            if (NULL != pcb->tcp_pcb) {
                TCP_SET_QUIET_CLOSE(pcb->tcp_pcb);
            }
            OSSL_SET_QUIET_CLOSE(pcb->ossl_ssl);
        } else {
            lune_log(LUNE_INFO, "quiet closure already set on ssl socket %d",
                SOCKET_GET_ID(sk));
        }

        break;
    case LUNE_SOCKET_OPT_SET_SSL:
    {
        ossl_ctx_t *ctx;

        if (unlikely(NULL == opt_val
            || opt_len != sizeof(unsigned int)
            || LUNE_INVALID_ID == *(const unsigned int *)opt_val)) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        if (NULL != pcb->ossl_ssl) {
            return ERR_SET_ERR(LUNE_ERR_ALREADY_SET);
        }

        if (NULL == (ctx = ossl_get_ctx(*(const unsigned int *)opt_val))) {
            return ERR_GET_LAST_ERR();
        }

        if (!OSSL_CTX_IS_CLIENT(ctx)) {
            return ERR_SET_ERR(LUNE_ERR_SSL_TYPE_ERR);
        }

        if (NULL == (pcb->ossl_ssl = ossl_create_ssl(ctx))) {
            return ERR_GET_LAST_ERR();
        }

        if (OSSL_CTX_IS_QUIET_CLOSE(ctx)) {
            /* reset close */
            SSL_SET_RST_CLOSE(pcb);
            if (NULL != pcb->tcp_pcb) {
                TCP_SET_RST_CLOSE(pcb->tcp_pcb);
            }
            /* pcb->ossl_ssl inherits quiet mode from ctx, no need to set it explicitly */
        } else {
            /* normal close */
            SSL_SET_NORMAL_CLOSE(pcb);
            if (NULL != pcb->tcp_pcb) {
                TCP_SET_NORMAL_CLOSE(pcb->tcp_pcb);
            }
            /* pcb->ossl_ssl inherits normal mode from ctx, no need to set it explicitly */
        }

        break;
    }
    case LUNE_SOCKET_OPT_SET_TCP_MSS:
    {
        unsigned short mss;

        if (NULL == opt_val || opt_len != sizeof(unsigned short)) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        if (NULL == pcb->tcp_pcb) {
            /* mss can only be set after bind */
            return ERR_SET_ERR(LUNE_ERR_NOT_BOUND);
        }

        lune_assert(NULL != pcb->tcp_pcb->ipp);

        mss = tcp_get_max_mss(pcb->tcp_pcb);
        if (*(const unsigned short *)opt_val > mss) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        mss = *(const unsigned short *)opt_val;
        pcb->tcp_pcb->mss = mss;
        pcb->tcp_pcb->cwnd = mss * TCP_INIT_CWND_SEG_NUM;
        pcb->tcp_pcb->ss_thresh = mss * TCP_INIT_SS_THRESH_SEG_NUM;
        break;
    }
    default:
        return ERR_SET_ERR(LUNE_ERR_OPT_NOT_FOUND);
    }

    return 0;
}

static int ssl_socket_close(socket_t *sk)
{
    ssl_pcb_t *pcb = &sk->pcb.ssl;
    int ret;

    if (NULL == pcb->tcp_sk
        || !socket_is_added(pcb->tcp_sk)) {
        /* client socket not bound or connect yet */
        if (NULL != pcb->tcp_sk) {
            /* bound but tcp yet connected */
            socket_put(pcb->tcp_sk);
            lune_assert(!pcb->tcp_ops->close((socket_t *)pcb->tcp_sk));
            lune_assert(!socket_close(pcb->tcp_sk));
            pcb->tcp_sk = NULL;
            pcb->tcp_pcb = NULL;
            pcb->ifp = NULL;
        }

        if (NULL != pcb->ossl_ssl) {
            ossl_delete_ssl(pcb->ossl_ssl);
            pcb->ossl_ssl = NULL;
        }

        return 0;
    }

    if (unlikely(NULL == pcb->ossl_ssl)) {
        /*
            internal error occurred and ssl was deleted but socket remains alive.
            it happens when there was asynchronous request in the queue to CP in
            the meantime of the occurrence of error. only ssl was deleted but socket
            has to wait until the queue is emptied. closure in progress, just log it
            and return error code
        */
        lune_assert(LUNE_ERR_NO_ERR != pcb->err_code);

        lune_log(LUNE_INFO, "failed to close ssl connection %s due to internal error: %s",
            tcp_print_pcb_4tuple(pcb->tcp_pcb),
            ERR_GET_ERR_STR(pcb->err_code));

        return pcb->err_code;
    }

    if (pcb->cp_req_cnt > 0) {
        /*
            there is asynchronous request in the queue to CP. normal socket closure
            should not be done until request processed, to avoid multi-thread access
            of ssl data and/or disorder of requests
        */
        lune_assert(CORE_IS_CP_BOUND());
        lune_assert(CORE_NP_MAX_BOUND_CP_NUM != pcb->cp_idx);
        lune_assert(CORE_NP_IS_CP_ACTIVE(pcb->cp_idx));
        goto ASYNC_CLOSE;
    } else {
        /* no cached data in request queue */
        lune_assert(0 == pcb->cp_send_len);
    }

    if (SSL_IS_ESTABLISHED(pcb)) {
        /* synchronous closure */
        ret = OSSL_CLOSE(pcb->ossl_ssl);
        if (unlikely(0 > ret)) {
            /*
                something went wrong while closing ssl, log it and move on to close
                tcp connection
            */
            lune_log(LUNE_INFO, "failed to close ssl connection %s: %s",
                tcp_print_pcb_4tuple(pcb->tcp_pcb),
                ERR_GET_LAST_ERR_STR());

            if (likely(NULL != pcb->ifp)) {
                NET_IF_SSL_INC_FAILED_CONN(pcb->ifp);
            }
        } else {
            if (likely(OSSL_SYNC_SEND_ON(pcb->ossl_ssl))) {
                /* normal close, send close_notify message */
                int sent_len;
                OSSL_SYNC_SEND_SET_OFF(pcb->ossl_ssl);
                if ((int)OSSL_GET_SEND_BUF_LEN() != (sent_len = ssl_sync_send(sk,
                    OSSL_GET_SEND_BUF(), OSSL_GET_SEND_BUF_LEN()))) {
                    /*
                        something went wrong while sending close_notify message, log it and
                        move on to close tcp connection
                    */
                    if (likely(sent_len < 0)) {
                        lune_log(LUNE_INFO, "failed to close ssl connection %s: %s",
                            tcp_print_pcb_4tuple(pcb->tcp_pcb),
                            ERR_GET_ERR_STR(sent_len));
                    } else {
                        lune_assert(0 == sent_len);
                        sent_len = ERR_SET_ERR(LUNE_ERR_TCP_CWND_FULL);
                        lune_log(LUNE_INFO, "failed to close ssl connection %s: "
                            "ssl shutdown message not sent due to %s",
                            tcp_print_pcb_4tuple(pcb->tcp_pcb),
                            ERR_GET_ERR_STR(sent_len));
                    }
                    if (likely(NULL != pcb->ifp)) {
                        NET_IF_SSL_INC_FAILED_CONN(pcb->ifp);
                    }
                } else {
                    if (likely(NULL != pcb->ifp)) {
                        NET_IF_SSL_INC_CLOSED_CONN(pcb->ifp);
                    }
                }
                OSSL_CLEAR_SEND_BUF();
            } else {
                /* reset or quiet close */
                if (likely(NULL != pcb->ifp)) {
                    NET_IF_SSL_INC_CLOSED_CONN(pcb->ifp);
                }
            }
        }

        if (likely(NULL != pcb->ifp)) {
            NET_IF_SSL_DEC_CONCURRENT_CONN(pcb->ifp);
        }
    } else {
        /*
            client socket connecting but not established yet. instead of calling openssl
            shutdown function, just close the underlying tcp connection
        */
        lune_assert(SSL_IS_ATTEMPTING(pcb));
    }

    ossl_delete_ssl(pcb->ossl_ssl);
    pcb->ossl_ssl = NULL;

    SOCKET_PUSH_CB_SK(pcb->tcp_sk);
    /* close tcp socket */
    ret = lune_close_in_cb();
    SOCKET_POP_CB_SK();

    return ret;

ASYNC_CLOSE:
    if (0 == (ret = ossl_async_close_socket(pcb->ossl_ssl, sk, pcb->cp_idx, SSL_GET_CLOSE_TYPE(pcb)))) {
        if (SSL_CLOSE_TYPE_NORMAL != SSL_GET_CLOSE_TYPE(pcb)) {
            /* reset or quiet close */
            if (likely(NULL != pcb->ifp)) {
                NET_IF_SSL_INC_CLOSED_CONN(pcb->ifp);
                NET_IF_SSL_DEC_CONCURRENT_CONN(pcb->ifp);
            }
        }

        socket_hold(sk);
        pcb->cp_req_cnt++;
        return 0;
    }

    /* queue full, just return error so it can be retried later */
    lune_log(LUNE_INFO, "failed to close socket on async mode on ssl connection %s: %s",
        tcp_print_pcb_4tuple(pcb->tcp_pcb),
        ERR_GET_ERR_STR(ret));

    return ret;
}

static int ssl_socket_send(socket_t *sk, const unsigned char *buf, unsigned int buf_len)
{
    ssl_pcb_t *pcb = &sk->pcb.ssl;
    void *ssl = pcb->ossl_ssl;
    int sent_len, enc_sent_len, err;
    unsigned int tcp_data_len, ssl_data_len;

    if (!SSL_IS_ESTABLISHED(pcb)) {
        lune_log(LUNE_INFO, "attempted to send data while connection"
            " has not been established on ssl socket %d", SOCKET_GET_ID(sk));
        return ERR_SET_ERR(LUNE_ERR_SOCKET_NOT_CONNECTED);
    }

    if (0 == (tcp_data_len = tcp_get_data_room(pcb->tcp_pcb))) {
        return 0;
    }

    ssl_data_len = (unsigned int)(tcp_data_len / SSL_SEND_ENCRYPTED_DATA_RATIO);

    if (CORE_IS_CP_BOUND()) {
        if (CORE_NP_MAX_BOUND_CP_NUM == pcb->cp_idx
            || !CORE_NP_IS_CP_ACTIVE(pcb->cp_idx)) {
            lune_assert(CORE_NP_MAX_BOUND_CP_NUM != (pcb->cp_idx = core_get_next_bound_cp_idx()));
        } else {
            /*
                ssl socket already bound to certain active CP
            */
        }

        /* ssl_data_len could be less than pcb->cp_send_len */
        if (((int)ssl_data_len - (int)pcb->cp_send_len) < SSL_SEND_MIN_DATA_ROOM) {
            /* window too small, wait until more sent data acknowledged */
            return 0;
        }

        buf_len = buf_len > (ssl_data_len - pcb->cp_send_len)
            ? (ssl_data_len - pcb->cp_send_len) : buf_len;
        goto ASYNC_SEND;
    }

    /* synchronous send */
    if (ssl_data_len < SSL_SEND_MIN_DATA_ROOM) {
        return 0;        
    }

    buf_len = buf_len > ssl_data_len ? ssl_data_len : buf_len;

    sent_len = OSSL_SEND(ssl, buf, buf_len);
    if (unlikely(0 >= sent_len)) {
        err = sent_len;
        ossl_status_en status = ossl_get_status(ssl, &err);
        switch (status) {
        case OSSL_STATUS_WANT_IO:
            /* wait for ssl to be readable */
            break;
        default:
            lune_log(LUNE_INFO, "failed to send data with status %d due to SSL error %d"
                " on ssl connnection %s",
                status,
                err,
                tcp_print_pcb_4tuple(pcb->tcp_pcb));
            return ERR_SET_ERR(LUNE_ERR_SSL_INTERNAL);
        }

        return 0;
    }

    lune_assert(OSSL_SYNC_SEND_ON(ssl));
    lune_assert((unsigned int)sent_len == buf_len);

    OSSL_SYNC_SEND_SET_OFF(ssl);
    if ((int)OSSL_GET_SEND_BUF_LEN() != (enc_sent_len = ssl_sync_send(sk,
        OSSL_GET_SEND_BUF(), OSSL_GET_SEND_BUF_LEN()))) {
        if (likely(enc_sent_len < 0)) {
            lune_log(LUNE_INFO, "failed to send data on ssl connection %s: %s",
                tcp_print_pcb_4tuple(pcb->tcp_pcb),
                ERR_GET_ERR_STR(enc_sent_len));
        } else {
            lune_log(LUNE_INFO, "failed to send data on ssl connection %s: "
                "ssl data of %d bytes not sent due to tcp congestion window full",
                tcp_print_pcb_4tuple(pcb->tcp_pcb),
                enc_sent_len);
        }
        OSSL_CLEAR_SEND_BUF();
        return enc_sent_len;
    }

    OSSL_CLEAR_SEND_BUF();

    if (likely(NULL != pcb->ifp)) {
        NET_IF_SSL_ADD_DATA_ENC(pcb->ifp, sent_len);
    }

    return sent_len;

ASYNC_SEND:
    if (0 == (err = ossl_async_handle_send_pkt(ssl, sk, buf, buf_len, pcb->cp_idx))) {
        /* async mode */
        socket_hold(sk);
        pcb->cp_req_cnt++;
        pcb->cp_send_len += buf_len;
        return buf_len;
    }

    lune_log(LUNE_INFO, "failed to handle sending packet on async mode"
        " on ssl connection %s: %s",
        tcp_print_pcb_4tuple(pcb->tcp_pcb),
        ERR_GET_ERR_STR(err));
    return err;
}

static int ssl_socket_send_pkts(socket_t *sk,
    lune_socket_send_pkt_t *pkts, unsigned int pkt_num, unsigned int mode __attribute__((unused)))
{
    unsigned int i;
    int total_sent_len;
    unsigned char buf[SSL_SEND_ORIG_PKT_MAX_SIZE];

    /* LUNE_SOCKET_SEND_PKTS_UNCHANGED not supported */

    total_sent_len = 0;
    for (i = 0; i < pkt_num; i++) {
        if ((total_sent_len + pkts[i].len) > SSL_SEND_ORIG_PKT_MAX_SIZE) {
            memcpy(buf + total_sent_len,
                pkts[i].buf, SSL_SEND_ORIG_PKT_MAX_SIZE - total_sent_len);
            total_sent_len = SSL_SEND_ORIG_PKT_MAX_SIZE;
            break;
        }
        memcpy(buf + total_sent_len, pkts[i].buf, pkts[i].len);
        total_sent_len += pkts[i].len;
    }

    return ssl_socket_send(sk, buf, total_sent_len);
}

socket_ops_t g_socket_ops_ssl = {
    .create = (socket_create_func_t)ssl_socket_create,
    .bind = (socket_bind_func_t)ssl_socket_bind,
    .connect = (socket_connect_func_t)ssl_socket_connect,
    .listen = NULL,
    .send = (socket_send_func_t)ssl_socket_send,
    .send_pkts = (socket_send_pkts_func_t)ssl_socket_send_pkts,
    .sendto = NULL,
    .get_opt = (socket_get_opt_func_t)ssl_socket_get_opt,
    .set_opt = (socket_set_opt_func_t)ssl_socket_set_opt,
    .close = (socket_close_func_t)ssl_socket_close,
    .hash = NULL,
    .compare = NULL,
    .get_max_hdr_len = NULL,
};

/********** ssl listen socket **********/

static __thread lune_tcp_socket_callback_t s_ssl_listen_tcp_listen_socket_cb = {
    .connect = NULL,
    .accept = (lune_tcp_socket_accept_callback_func_t)ssl_tcp_socket_accept,
    .recv = (lune_tcp_socket_recv_callback_func_t)ssl_tcp_socket_recv,
    .closewait = (lune_tcp_socket_closewait_callback_func_t)ssl_tcp_socket_closewait,
    .error = (lune_tcp_socket_error_callback_func_t)ssl_tcp_socket_error,
    .close = (lune_tcp_socket_close_callback_func_t)ssl_tcp_socket_close,
    .data = NULL,
};

static int ssl_listen_socket_create(socket_t *listen_sk)
{
    ssl_listen_pcb_t *pcb = &listen_sk->pcb.ssl_listen;
    int err;

    if (NULL == (pcb->tcp_listen_sk = socket_create(LUNE_SOCKET_TCP_LISTEN))) {
        err = ERR_GET_LAST_ERR();
        goto ERR_1;
    }

    socket_hold(pcb->tcp_listen_sk);
    pcb->tcp_listen_pcb = &pcb->tcp_listen_sk->pcb.tcp_listen;
    pcb->tcp_listen_ops = socket_get_socket_ops(LUNE_SOCKET_TCP_LISTEN);
    pcb->ossl_ctx = NULL;
    memset(&pcb->cb, 0x00, sizeof(lune_ssl_socket_callback_t));
    pcb->flags = 0;

    s_ssl_listen_tcp_listen_socket_cb.data = listen_sk;
    if (0 != (err = pcb->tcp_listen_ops->set_opt(pcb->tcp_listen_sk,
        LUNE_SOCKET_OPT_SET_CALLBACK,
        (const unsigned char *)&s_ssl_listen_tcp_listen_socket_cb,
        sizeof(s_ssl_listen_tcp_listen_socket_cb)))) {
        s_ssl_listen_tcp_listen_socket_cb.data = NULL;
        goto ERR_2;
    }
    s_ssl_listen_tcp_listen_socket_cb.data = NULL;

    return 0;

ERR_2:
    socket_put(pcb->tcp_listen_sk);
    lune_assert(!socket_close(pcb->tcp_listen_sk));
    pcb->tcp_listen_sk = NULL;

ERR_1:
    return err;
}

static int ssl_listen_socket_close(socket_t *listen_sk)
{
    ssl_listen_pcb_t *pcb = &listen_sk->pcb.ssl_listen;
    int err;

    if (NULL != pcb->ossl_ctx) {
        ossl_ctx_put(pcb->ossl_ctx);
        pcb->ossl_ctx = NULL;
    }

    socket_put(pcb->tcp_listen_sk);

    lune_assert(!pcb->tcp_listen_ops->close(pcb->tcp_listen_sk));
    err = socket_close(pcb->tcp_listen_sk);
    pcb->tcp_listen_sk = NULL;

    return err;
}

static int ssl_listen_socket_bind(socket_t *sk, const void *arg, unsigned int arg_len)
{
    ssl_listen_pcb_t *pcb = &sk->pcb.ssl_listen;
    return pcb->tcp_listen_ops->bind(pcb->tcp_listen_sk, arg, arg_len);
}

static int ssl_listen_socket_listen(socket_t *sk, unsigned int backlog)
{
    ssl_listen_pcb_t *pcb = &sk->pcb.ssl_listen;

    if (NULL == pcb->ossl_ctx) {
        return ERR_SET_ERR(LUNE_ERR_SSL_NOT_SET);
    }

    if (!OSSL_CTX_IS_CERT_SET(pcb->ossl_ctx)) {
        return ERR_SET_ERR(LUNE_ERR_SSL_CERT_NOT_SET);
    }

    return pcb->tcp_listen_ops->listen(pcb->tcp_listen_sk, backlog);
}

static int ssl_listen_socket_get_opt(socket_t *sk,
    lune_socket_opt_en opt, unsigned char *opt_val, unsigned int opt_len)
{
    ssl_listen_pcb_t *pcb = &sk->pcb.ssl_listen;

    switch (opt) {
    case LUNE_SOCKET_OPT_GET_TCP_MSS:
        if (unlikely(NULL == opt_val || opt_len != sizeof(unsigned short))) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        if (NULL == pcb->tcp_listen_pcb || NULL == pcb->tcp_listen_pcb->ipp) {
            return ERR_SET_ERR(LUNE_ERR_NOT_BOUND);
        }

        *(unsigned short *)opt_val = pcb->tcp_listen_pcb->init_mss;
        break;
    default:
        return ERR_SET_ERR(LUNE_ERR_OPT_NOT_FOUND);
    }

    return 0;
}

static int ssl_listen_socket_set_opt(socket_t *sk,
    lune_socket_opt_en opt, const unsigned char *opt_val, unsigned int opt_len)
{
    ssl_listen_pcb_t *pcb = &sk->pcb.ssl_listen;

    switch (opt) {
    case LUNE_SOCKET_OPT_SET_CALLBACK:
        if (NULL == opt_val
            || opt_len != sizeof(lune_ssl_socket_callback_t)) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        if (NULL != ((const lune_ssl_socket_callback_t *)opt_val)->connect) {
            lune_log(LUNE_INFO, "attempted to register connect event"
                " on ssl listen socket %d", SOCKET_GET_ID(sk));
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        memcpy(&pcb->cb, opt_val, sizeof(lune_ssl_socket_callback_t));
        break;
    case LUNE_SOCKET_OPT_SET_NORMAL_CLOSE:
        if (unlikely(NULL != opt_val || 0 != opt_len)) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        if (NULL == pcb->ossl_ctx) {
            /*
                SSL has to be set before closure mode, or the mode will be overwritten
                with the one inherited from SSL set to the socket
            */
            return ERR_SET_ERR(LUNE_ERR_NOT_SET);
        }

        if (likely(SSL_GET_CLOSE_TYPE(pcb) != SSL_CLOSE_TYPE_NORMAL)) {
            SSL_SET_NORMAL_CLOSE(pcb);
            TCP_SET_NORMAL_CLOSE(pcb->tcp_listen_pcb);
        } else {
            lune_log(LUNE_INFO, "normal closure already set on ssl listen socket %d",
                SOCKET_GET_ID(sk));
        }

        break;
    case LUNE_SOCKET_OPT_SET_RST_CLOSE:
        if (unlikely(NULL != opt_val || 0 != opt_len)) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        if (NULL == pcb->ossl_ctx) {
            /*
                SSL has to be set before closure mode, or the mode will be overwritten
                with the one inherited from SSL set to the socket
            */
            return ERR_SET_ERR(LUNE_ERR_NOT_SET);
        }

        if (likely(SSL_GET_CLOSE_TYPE(pcb) != SSL_CLOSE_TYPE_RST)) {
            SSL_SET_RST_CLOSE(pcb);
            TCP_SET_RST_CLOSE(pcb->tcp_listen_pcb);
        } else {
            lune_log(LUNE_INFO, "reset closure already set on ssl listen socket %d",
                SOCKET_GET_ID(sk));
        }

        break;
    case LUNE_SOCKET_OPT_SET_QUIET_CLOSE:
        if (unlikely(NULL != opt_val || 0 != opt_len)) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        if (NULL == pcb->ossl_ctx) {
            /*
                SSL has to be set before closure mode, or the mode will be overwritten
                with the one inherited from SSL set to the socket
            */
            return ERR_SET_ERR(LUNE_ERR_NOT_SET);
        }

        if (likely(SSL_GET_CLOSE_TYPE(pcb) != SSL_CLOSE_TYPE_QUIET)) {
            SSL_SET_QUIET_CLOSE(pcb);
            TCP_SET_QUIET_CLOSE(pcb->tcp_listen_pcb);
        } else {
            lune_log(LUNE_INFO, "quiet closure already set on ssl listen socket %d",
                SOCKET_GET_ID(sk));
        }

        break;
    case LUNE_SOCKET_OPT_SET_SSL:
    {
        ossl_ctx_t *ctx;

        if (unlikely(NULL == opt_val
            || opt_len != sizeof(unsigned int)
            || LUNE_INVALID_ID == *(const unsigned int *)opt_val)) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        if (NULL != pcb->ossl_ctx) {
            return ERR_SET_ERR(LUNE_ERR_ALREADY_SET);
        }

        if (NULL == (ctx = ossl_get_ctx(*(const unsigned int *)opt_val))) {
            return ERR_GET_LAST_ERR();
        }

        if (OSSL_CTX_IS_CLIENT(ctx)) {
            return ERR_SET_ERR(LUNE_ERR_SSL_TYPE_ERR);
        }

        if (OSSL_CTX_IS_QUIET_CLOSE(ctx)) {
            /* reset close */
            SSL_SET_RST_CLOSE(pcb);
            TCP_SET_RST_CLOSE(pcb->tcp_listen_pcb);
        } else {
            /* normal close */
            SSL_SET_NORMAL_CLOSE(pcb);
            TCP_SET_NORMAL_CLOSE(pcb->tcp_listen_pcb);
        }

        pcb->ossl_ctx = ctx;
        ossl_ctx_hold(ctx);
        break;
    }
    case LUNE_SOCKET_OPT_SET_TCP_MSS:
    {
        unsigned short mss;

        if (NULL == opt_val || opt_len != sizeof(unsigned short)) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        if (NULL == pcb->tcp_listen_pcb || NULL == pcb->tcp_listen_pcb->ipp) {
            /* mss can only be set after bind */
            return ERR_SET_ERR(LUNE_ERR_NOT_BOUND);
        }

        mss = tcp_listen_get_max_mss(pcb->tcp_listen_pcb);
        if (*(const unsigned short *)opt_val > mss) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        mss = *(const unsigned short *)opt_val;
        pcb->tcp_listen_pcb->init_mss = mss;
        pcb->tcp_listen_pcb->init_cwnd = mss * TCP_INIT_CWND_SEG_NUM;
        pcb->tcp_listen_pcb->init_ss_thresh = mss * TCP_INIT_SS_THRESH_SEG_NUM;
        break;
    }
    default:
        return ERR_SET_ERR(LUNE_ERR_OPT_NOT_FOUND);
    }

    return 0;
}

socket_ops_t g_socket_ops_ssl_listen = {
    .create = (socket_create_func_t)ssl_listen_socket_create,
    .bind = (socket_bind_func_t)ssl_listen_socket_bind,
    .connect = NULL,
    .listen = (socket_listen_func_t)ssl_listen_socket_listen,
    .send = NULL,
    .send_pkts = NULL,
    .sendto = NULL,
    .get_opt = (socket_get_opt_func_t)ssl_listen_socket_get_opt,
    .set_opt = (socket_set_opt_func_t)ssl_listen_socket_set_opt,
    .close = (socket_close_func_t)ssl_listen_socket_close,
    .hash = NULL,
    .compare = NULL,
    .get_max_hdr_len = NULL,
};

unsigned int lune_add_ssl(lune_ssl_version_en ver, lune_ssl_type_en type)
{
    SCHED_CHECK_POINT();

    if (unlikely(ver < LUNE_SSL_VERSION_SSLV3
        || ver >= LUNE_SSL_VERSION_MAX
        || type < LUNE_SSL_CLIENT
        || type >= LUNE_SSL_MAX)) {
        return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
    }

    return ossl_create_ctx(ver, type);
}

int lune_del_ssl(unsigned int id)
{
    SCHED_CHECK_POINT();
    return ossl_delete_ctx(id);
}

int lune_get_ssl_opt(unsigned int id,
    lune_ssl_opt_en opt, unsigned char *opt_val, unsigned int opt_len)
{
    ossl_ctx_t *ctx;
    int err;

    SCHED_CHECK_POINT();

    if (unlikely(LUNE_INVALID_ID == id)) {
        return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
    }

    if (NULL == (ctx = ossl_get_ctx(id))) {
        return ERR_GET_LAST_ERR();
    }

    switch (opt) {
    case LUNE_SSL_OPT_GET_SESS_CACHE_MODE:
        if (NULL == opt_val || opt_len != sizeof(lune_ssl_sess_cache_mode_en)) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        err = ossl_get_sess_cache_mode(ctx, (lune_ssl_sess_cache_mode_en *)opt_val);
        break;
    default:
        return ERR_SET_ERR(LUNE_ERR_OPT_NOT_FOUND);
    }

    return err;
}

int lune_set_ssl_opt(unsigned int id,
    lune_ssl_opt_en opt, const unsigned char *opt_val, unsigned int opt_len)
{
    ossl_ctx_t *ctx;
    int err;

    SCHED_CHECK_POINT();

    if (unlikely(LUNE_INVALID_ID == id)) {
        return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
    }

    if (NULL == (ctx = ossl_get_ctx(id))) {
        return ERR_GET_LAST_ERR();
    }

    switch (opt) {
    case LUNE_SSL_OPT_SET_CERT:
    {
        const lune_ssl_cert_t *cert;

        if (NULL == opt_val || opt_len != sizeof(lune_ssl_cert_t)) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        cert = (const lune_ssl_cert_t *)opt_val;
        if (NULL == cert->cert_file || NULL == cert->priv_key) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        err = ossl_load_certificate(ctx, cert->cert_file, cert->priv_key);
        break;
    }
    case LUNE_SSL_OPT_SET_CIPHERS:
        if (NULL == opt_val || opt_len != sizeof(lune_ssl_ciphers_t)) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        if (NULL == ((const lune_ssl_ciphers_t *)opt_val)->array
            || 0 == ((const lune_ssl_ciphers_t *)opt_val)->num) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        err = ossl_set_ciphers(ctx,
            ((const lune_ssl_ciphers_t *)opt_val)->array,
            ((const lune_ssl_ciphers_t *)opt_val)->num);
        break;
    case LUNE_SSL_OPT_SET_SESS_CACHE_MODE:
        if (NULL == opt_val || opt_len != sizeof(lune_ssl_sess_cache_mode_en)) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        if ((*(const lune_ssl_sess_cache_mode_en *)opt_val) < LUNE_SSL_SESS_CACHE_OFF
            || (*(const lune_ssl_sess_cache_mode_en *)opt_val) >= LUNE_SSL_SESS_CACHE_MAX) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        err = ossl_set_sess_cache_mode(ctx, *(const lune_ssl_sess_cache_mode_en *)opt_val);
        break;
    case LUNE_SSL_OPT_SET_QUIET_CLOSE:
        if (NULL != opt_val || 0 != opt_len) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        OSSL_CTX_SET_QUIET_CLOSE(ctx);
        err = 0;
        break;
    case LUNE_SSL_OPT_SET_NORMAL_CLOSE:
        if (NULL != opt_val || 0 != opt_len) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        OSSL_CTX_SET_NORMAL_CLOSE(ctx);
        err = 0;
        break;
    default:
        return ERR_SET_ERR(LUNE_ERR_OPT_NOT_FOUND);
    }

    return err;
}

const char *lune_get_ssl_cipher_str(lune_ssl_cipher_en cipher)
{
    if (cipher < 0 || cipher >= LUNE_SSL_CIPHER_MAX) {
        return NULL;
    }

    return ossl_get_cipher_str(cipher);
}

int ssl_async_send(socket_t *sk,
    const unsigned char *buf, unsigned int len, unsigned int data_len)
{
    ssl_pcb_t *pcb = &sk->pcb.ssl;
    int sent_len;

#ifdef LUNE_DEBUG
    lune_assert(NULL != pcb->tcp_sk);
    lune_assert(!SOCKET_IS_CLOSED(pcb->tcp_sk));
#endif

    if ((int)len != (sent_len = pcb->tcp_ops->send((socket_t *)pcb->tcp_sk, buf, len))) {
        /* failed to send all data, close the socket */
        if (sent_len < 0) {
            pcb->err_code = sent_len;
        } else {
            lune_assert(0 == sent_len);
            pcb->err_code = sent_len = ERR_SET_ERR(LUNE_ERR_TCP_CWND_FULL);
        }

        lune_log(LUNE_INFO, "failed to send %d data on ssl connection %s: %s",
            len,
            tcp_print_pcb_4tuple(pcb->tcp_pcb),
            ERR_GET_ERR_STR(sent_len));

        if (pcb->cp_req_cnt > 0) {
            /* all asynchronous requests will be skipped and then socket will be closed */
            ossl_delete_ssl(pcb->ossl_ssl);
            pcb->ossl_ssl = NULL;
        } else {
            ssl_teardown_socket(pcb);
        }

        return sent_len < 0 ? sent_len : 0;
    }

    if (SSL_IS_ESTABLISHED(pcb) && data_len > 0) {
        pcb->cp_send_len -= data_len;
        if (likely(NULL != pcb->ifp)) {
            NET_IF_SSL_ADD_DATA_ENC(pcb->ifp, data_len);
        }
    }

    return 0;
}

int ssl_async_normal_close(socket_t *sk, const unsigned char *buf, unsigned int len)
{
    ssl_pcb_t *pcb = &sk->pcb.ssl;
    int ret, sent_len;

#ifdef LUNE_DEBUG
    lune_assert(0 == pcb->cp_req_cnt);      /* the last response */
    lune_assert(0 == pcb->cp_send_len);
    lune_assert(SOCKET_IS_CLOSED(sk));
    lune_assert(NULL != pcb->tcp_sk);
    lune_assert(!SOCKET_IS_CLOSED(pcb->tcp_sk));
#endif

    if ((int)len != (sent_len = pcb->tcp_ops->send((socket_t *)pcb->tcp_sk, buf, len))) {
        /* failed to send close_notify message, close the socket */
        if (sent_len < 0) {
            pcb->err_code = sent_len;
            lune_log(LUNE_INFO, "failed to send %d data on ssl connection %s: %s",
                len,
                tcp_print_pcb_4tuple(pcb->tcp_pcb),
                ERR_GET_ERR_STR(sent_len));
        } else {
            pcb->err_code = ERR_SET_ERR(LUNE_ERR_SSL_INTERNAL);
            lune_log(LUNE_INFO, "less data sent on ssl connection %s: %d expected but %d sent",
                tcp_print_pcb_4tuple(pcb->tcp_pcb),
                len,
                sent_len);
        }

        ssl_teardown_socket(pcb);

        return sent_len < 0 ? sent_len : 0;
    }

    if (likely(NULL != pcb->ifp)) {
        NET_IF_SSL_INC_CLOSED_CONN(pcb->ifp);
        NET_IF_SSL_DEC_CONCURRENT_CONN(pcb->ifp);
    }

    ossl_delete_ssl(pcb->ossl_ssl);
    pcb->ossl_ssl = NULL;

    SOCKET_PUSH_CB_SK(pcb->tcp_sk);
    /* close tcp socket */
    ret = lune_close_in_cb();
    SOCKET_POP_CB_SK();

    return ret;
}

int ssl_async_passive_close(socket_t *sk)
{
    ssl_pcb_t *pcb = &sk->pcb.ssl;
    int err = 0;

    lune_assert(0 == pcb->cp_send_len);

    if (NULL != pcb->cb.closewait) {
        SOCKET_PUSH_CB_SK(sk);
        pcb->cb.closewait(pcb->cb.data);
        SOCKET_POP_CB_SK();
    }

    if (NULL != pcb->ossl_ssl) {
        /* socket not close in callback closewait(), wait for the peer to close tcp connection */
        if (likely(NULL != pcb->ifp)) {
            NET_IF_SSL_INC_CLOSED_CONN(pcb->ifp);
            NET_IF_SSL_DEC_CONCURRENT_CONN(pcb->ifp);
        }

        ossl_delete_ssl(pcb->ossl_ssl);
        pcb->ossl_ssl = NULL;

        if (SSL_IS_TCP_CLWAIT(pcb)) {
            /* tcp passive close, just close it */
            SOCKET_PUSH_CB_SK(pcb->tcp_sk);
            err = lune_close_in_cb();
            SOCKET_POP_CB_SK();
        }
    }

    return err;
}

int ssl_async_tcp_close(socket_t *sk)
{
    ssl_pcb_t *pcb = &sk->pcb.ssl;
    int ret;

#ifdef LUNE_DEBUG
    lune_assert(0 == pcb->cp_req_cnt);      /* the last response */
    lune_assert(0 == pcb->cp_send_len);
    lune_assert(SOCKET_IS_CLOSED(sk));
    lune_assert(NULL != pcb->tcp_sk);
    lune_assert(!SOCKET_IS_CLOSED(pcb->tcp_sk));
#endif

    ossl_delete_ssl(pcb->ossl_ssl);
    pcb->ossl_ssl = NULL;

    /* close tcp socket, either reset or quiet close */
    SOCKET_PUSH_CB_SK(pcb->tcp_sk);
    ret = lune_close_in_cb();
    SOCKET_POP_CB_SK();

    return ret;
}

int ssl_local_init(void)
{
    return ossl_local_init();
}

void ssl_local_fini(void)
{
    ossl_local_fini();
}

int ssl_init(void)
{
    return ossl_init();
}

void ssl_fini(void)
{
    ossl_fini();
}
