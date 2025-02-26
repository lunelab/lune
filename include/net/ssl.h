/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2024 Lune Reseau, Inc.
 */

#ifndef __SSL_H_PRE__
#define __SSL_H_PRE__

#include "lune/list.h"
#include "lune/ssl.h"

#include "drv/net_if.h"
#include "net/ossl.h"
#include "net/socket.h"
#include "net/tcp.h"

#define SSL_RECV_DECRYPTED_PKT_MAX_SIZE     (4096)

typedef struct _ssl_pcb {
    socket_x_t *tcp_sk;
    tcp_pcb_t *tcp_pcb;
    socket_ops_t *tcp_ops;
    net_if_t *ifp;
    ossl_ssl_t *ossl_ssl;
    lune_ssl_socket_callback_t cb;
    int err_code;
#define SSL_CLOSE_MASK                      0x0003
#define SSL_CLOSE_TYPE_NORMAL               0x0000
#define SSL_CLOSE_TYPE_RST                  0x0001
/* SSL_CLOSE_TYPE_QUIET: close connection without signaling the peer */
#define SSL_CLOSE_TYPE_QUIET                0x0002
#define SSL_GET_CLOSE_TYPE(pcb)             ((pcb)->flags & SSL_CLOSE_MASK)
#define SSL_SET_NORMAL_CLOSE(pcb)           \
    do { (pcb)->flags = (((pcb)->flags & (~SSL_CLOSE_MASK)) | SSL_CLOSE_TYPE_NORMAL); } while (0)
#define SSL_SET_RST_CLOSE(pcb)              \
    do { (pcb)->flags = (((pcb)->flags & (~SSL_CLOSE_MASK)) | SSL_CLOSE_TYPE_RST); } while (0)
#define SSL_SET_QUIET_CLOSE(pcb)            \
    do { (pcb)->flags = (((pcb)->flags & (~SSL_CLOSE_MASK)) | SSL_CLOSE_TYPE_QUIET); } while (0)
#define SSL_FLAG_ON(pcb, flag)              (((ssl_pcb_t *)(pcb))->flags & (flag))
#define SSL_SET_FLAG(pcb, flag)             \
    do { ((ssl_pcb_t *)(pcb))->flags |= (flag); } while (0)
#define SSL_CLEAR_FLAG(pcb, flag)           \
    do { ((ssl_pcb_t *)(pcb))->flags &= (~flag); } while (0)
#define SSL_ATTEMPT_FLAG                    0x0004
#define SSL_IS_ATTEMPTING(pcb)              SSL_FLAG_ON(pcb, SSL_ATTEMPT_FLAG)
#define SSL_SET_ATTEMPTING(pcb)             SSL_SET_FLAG(pcb, SSL_ATTEMPT_FLAG)
#define SSL_CLEAR_ATTEMPTING(pcb)           SSL_CLEAR_FLAG(pcb, SSL_ATTEMPT_FLAG)
#define SSL_ESTABLISH_FLAG                  0x0008
#define SSL_IS_ESTABLISHED(pcb)             SSL_FLAG_ON(pcb, SSL_ESTABLISH_FLAG)
#define SSL_SET_ESTABLISHED(pcb)            SSL_SET_FLAG(pcb, SSL_ESTABLISH_FLAG)
#define SSL_CLEAR_ESTABLISHED(pcb)          SSL_CLEAR_FLAG(pcb, SSL_ESTABLISH_FLAG)
#define SSL_PASSIVE_FLAG                    0x0010
#define SSL_IS_PASSIVE_CONN(pcb)            SSL_FLAG_ON(pcb, SSL_PASSIVE_FLAG)
#define SSL_SET_PASSIVE(pcb)                SSL_SET_FLAG(pcb, SSL_PASSIVE_FLAG)
#define SSL_SET_ACTIVE(pcb)                 SSL_CLEAR_FLAG(pcb, SSL_PASSIVE_FLAG)
#define SSL_TCP_CLWAIT_FLAG                 0x0020
#define SSL_IS_TCP_CLWAIT(pcb)              SSL_FLAG_ON(pcb, SSL_TCP_CLWAIT_FLAG)
#define SSL_SET_TCP_CLWAIT(pcb)             SSL_SET_FLAG(pcb, SSL_TCP_CLWAIT_FLAG)
#define SSL_CLEAR_TCP_CLWAIT(pcb)           SSL_CLEAR_FLAG(pcb, SSL_TCP_CLWAIT_FLAG)
    unsigned short flags;
    unsigned short cp_req_cnt;
    unsigned int cp_idx;
    unsigned int cp_send_len;
} ssl_pcb_t;

typedef struct _ssl_listen_pcb {
    socket_t *tcp_listen_sk;
    tcp_listen_pcb_t *tcp_listen_pcb;
    socket_ops_t *tcp_listen_ops;
    ossl_ctx_t *ossl_ctx;
    lune_ssl_socket_callback_t cb;
    unsigned short flags;                   /* the same as flags field in ssl_pcb_t */
} ssl_listen_pcb_t;

#endif

#ifndef __SSL_H__
#define __SSL_H__

#include "net/mac.h"
#include "net/pbuf.h"

#define ssl_async_reset_close(sk)           ssl_async_tcp_close(sk)
#define ssl_async_quiet_close(sk)           ssl_async_tcp_close(sk)

int ssl_local_init(void);
void ssl_local_fini(void);

int ssl_async_send(socket_t *sk,
    const unsigned char *buf, unsigned int len, unsigned int data_len);
int ssl_async_normal_close(socket_t *sk, const unsigned char *buf, unsigned int len);
int ssl_async_passive_close(socket_t *sk);
int ssl_async_tcp_close(socket_t *sk);
int ssl_async_handle_conn_established(socket_t *sk, ossl_ssl_t *ossl_ssl);
int ssl_async_recv(socket_t *sk,
    ossl_ssl_t *ossl_ssl, const unsigned char *buf, unsigned int len, int err);

int ssl_init(void);
void ssl_fini(void);

extern socket_ops_t g_socket_ops_ssl;
extern socket_ops_t g_socket_ops_ssl_listen;

#endif