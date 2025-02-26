/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2024 Lune Reseau, Inc.
 */

#ifndef __LUNE_TCP_H__
#define __LUNE_TCP_H__

#include "lune/socket.h"

#ifdef __cplusplus
extern "C" {
#endif

#define LUNE_TCP_HDR_LEN   (sizeof(lune_tcp_hdr_t))

/* max interval in ms */
#define LUNE_TCP_MAX_DELACK_INTVL           (1000)

#define LUNE_TCP_LISTEN_BACKLOG_UNLIMITED   (0)
/* for backlog greater than max, set it to unlimited */
#define LUNE_TCP_LISTEN_MAX_BACKLOG         (65535)
#define LUNE_TCP_LISTEN_DEFAULT_BACKLOG     (1024)

/* 1 - user data */
typedef void (*lune_tcp_socket_connect_callback_func_t)(void *);
/* 1 - fd, 2 - source ip & port, 3 - pointer to store user data */
typedef void (*lune_tcp_socket_accept_callback_func_t)(unsigned int, lune_socket_addr_t *, void **);
/* 1 - user data, 2 - buf, 3 - buflen */
typedef void (*lune_tcp_socket_recv_callback_func_t)(void *, const unsigned char *, unsigned int);
/* 1 - user data */
typedef void (*lune_tcp_socket_closewait_callback_func_t)(void *);
/* 1 - user data, 2 - error type */
typedef void (*lune_tcp_socket_error_callback_func_t)(void *, int);
/* 1 - user data, 2 - close type */
typedef void (*lune_tcp_socket_close_callback_func_t)(void *, unsigned int);

typedef struct _lune_tcp_socket_callback {
    lune_tcp_socket_connect_callback_func_t connect;
    lune_tcp_socket_accept_callback_func_t accept;
    lune_tcp_socket_recv_callback_func_t recv;
    lune_tcp_socket_closewait_callback_func_t closewait;
    lune_tcp_socket_error_callback_func_t error;
/* normal close with 4 handshakes */
#define LUNE_TCP_SOCKET_CLOSE_NORMAL                0
/* reset close, either send or receive RST packet */
#define LUNE_TCP_SOCKET_CLOSE_RST                   1
/* simply close it without interaction */
#define LUNE_TCP_SOCKET_CLOSE_QUIET                 2
/* close due to keep-alive timeout */
#define LUNE_TCP_SOCKET_CLOSE_KEEP_ALIVE_TIMEOUT    3
    lune_tcp_socket_close_callback_func_t close;
    void *data;
} lune_tcp_socket_callback_t;

typedef struct _lune_tcp_socket_keep_alive_param {
#define LUNE_TCP_SOCKET_KEEP_ALIVE_MAX_TIME     (3600 * 24)
    unsigned int time;
#define LUNE_TCP_SOCKET_KEEP_ALIVE_MIN_INTVL    (1)
#define LUNE_TCP_SOCKET_KEEP_ALIVE_MAX_INTVL    (1800)
    unsigned int intvl;
#define LUNE_TCP_SOCKET_KEEP_ALIVE_MIN_PROBES   (1)
    unsigned int probes;
} lune_tcp_socket_keep_alive_param_t;

#pragma pack(1)
typedef struct _lune_tcp_hdr {
    unsigned short src_port;
    unsigned short dst_port;
    unsigned int seq_no;
    unsigned int ack_no;
    unsigned char hdr_len;
    unsigned char flags;
    unsigned short win_size;
    unsigned short csum;
    unsigned short urg_ptr;
} lune_tcp_hdr_t;

typedef struct _lune_tcp_max_hdr {
    lune_tcp_hdr_t hdr;
    unsigned char opt[40];
} lune_tcp_max_hdr_t;
#pragma pack()

/*
    caller guarantees fields in TCP header is in network order
*/
int lune_tcp_calc_csum(lune_tcp_hdr_t *tcph,
    lune_ip_addr_t *src_ip,
    lune_ip_addr_t *dst_ip,
    unsigned short tcp_len,
    unsigned short *pcsum);

#ifdef __cplusplus
}
#endif

#endif