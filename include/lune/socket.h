/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2024 Lune Reseau, Inc.
 */

#ifndef __LUNE_SOCKET_H__
#define __LUNE_SOCKET_H__

#include "lune/ip.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum _lune_socket_type {
    LUNE_SOCKET_NET_IF = 0,
    LUNE_SOCKET_MAC,
    LUNE_SOCKET_IP,     /* ipv4/ipv6 datagram socket */
    LUNE_SOCKET_IPV4,   /* ipv4 raw socket */
    LUNE_SOCKET_IPV6,   /* reserved, not supported yet */
    LUNE_SOCKET_UDP,
    LUNE_SOCKET_TCP,
    LUNE_SOCKET_TCP_LISTEN,
    LUNE_SOCKET_TCP_BATCH_LISTEN,
    LUNE_SOCKET_TCP_PEER_LISTEN,
    LUNE_SOCKET_SSL,
    LUNE_SOCKET_SSL_BATCH_LISTEN,
    LUNE_SOCKET_SSL_LISTEN,
    LUNE_SOCKET_ICMP,
    LUNE_SOCKET_IGMP,
    LUNE_SOCKET_MAX,
} lune_socket_type_en;

typedef enum _lune_socket_opt {
    /* get options */
    LUNE_SOCKET_OPT_GET_SRC_IP_ID,

    /* tcp specific */
    LUNE_SOCKET_OPT_GET_TCP_MSS,
    LUNE_SOCKET_OPT_GET_TCP_DELACK_INTVL,   /* in ms */

    /* set options */
    LUNE_SOCKET_OPT_SET_CALLBACK = 256,
    LUNE_SOCKET_OPT_SET_CALLBACK_DATA,
    LUNE_SOCKET_OPT_CLEAR_CALLBACK,

    LUNE_SOCKET_OPT_SET_NORMAL_CLOSE,
    LUNE_SOCKET_OPT_SET_RST_CLOSE,
    LUNE_SOCKET_OPT_SET_QUIET_CLOSE,        /* close socket without notifying the other peer */

    /* tcp specific */
    LUNE_SOCKET_OPT_SET_TCP_MSS,
    LUNE_SOCKET_OPT_SET_TCP_ZERO_WIN,
    LUNE_SOCKET_OPT_CLEAR_TCP_ZERO_WIN,
    LUNE_SOCKET_OPT_SET_TCP_KEEP_ALIVE,
    LUNE_SOCKET_OPT_CLEAR_TCP_KEEP_ALIVE,
    LUNE_SOCKET_OPT_SET_TCP_DELACK,
    LUNE_SOCKET_OPT_CLEAR_TCP_DELACK,
    LUNE_SOCKET_OPT_CLEAR_TCP_EST_FASTACK,
    LUNE_SOCKET_OPT_SET_TCP_DELACK_INTVL,   /* in ms */

    LUNE_SOCKET_OPT_SET_ALL_OR_NONE_XMIT,
    LUNE_SOCKET_OPT_SET_SSL,
    LUNE_SOCKET_OPT_ADD_MEMBERSHIP,         /* multicast join group */
    LUNE_SOCKET_OPT_DROP_MEMBERSHIP,        /* multicast leave group */
} lune_socket_opt_en;

typedef struct _lune_socket_addr {
    union {
        unsigned int id;
        lune_ip_addr_t addr;
    };
    unsigned short port;
} lune_socket_addr_t;

typedef struct _lune_socket_v4_addr {
    union {
        unsigned int id;
        lune_ipv4_addr_t addr;
    };
    unsigned short port;
} lune_socket_v4_addr_t;

typedef struct _lune_socket_batch_listen_addr {
    unsigned int id;
    unsigned short start_port;
    unsigned short end_port;
} lune_socket_batch_listen_addr_t;

typedef struct _lune_socket_peer_listen_addr {
    unsigned int id;
    lune_ip_addr_t peer_addr;
    unsigned short port;
} lune_socket_peer_listen_addr_t;

typedef struct _lune_socket_send_pkt {
    const unsigned char *buf;
    unsigned int len;
} lune_socket_send_pkt_t;

unsigned int lune_socket(lune_socket_type_en type);

int lune_bind(unsigned int id, void *arg, unsigned int arg_len);

int lune_connect(unsigned int id, void *arg, unsigned int arg_len);

int lune_listen(unsigned int id, unsigned int backlog);

int lune_send(unsigned int id, const unsigned char *buf, unsigned int len);

/* packets may or may not be re-organized, depending on socket */
#define LUNE_SOCKET_SEND_PKTS_DEFAULT       (0)
/* packets are sent exactly as told, unchanged */
#define LUNE_SOCKET_SEND_PKTS_UNCHANGED     (1)

int lune_send_pkts(unsigned int id,
    lune_socket_send_pkt_t *pkts, unsigned int pkt_num, unsigned int mode);

int lune_sendto(unsigned int id, const unsigned char *buf, unsigned int len,
    const void *dst_addr, unsigned int dst_addr_len, const void *arg, unsigned int arg_len);

int lune_close(unsigned int id);

int lune_get_socket_opt(unsigned int id,
    lune_socket_opt_en opt, unsigned char *opt_val, unsigned int opt_len);

int lune_set_socket_opt(unsigned int id,
    lune_socket_opt_en opt, const unsigned char *opt_val, unsigned int opt_len);

/* the following are a set of socket functions called in cb event */

int lune_send_in_cb(const unsigned char *buf, unsigned int len);

int lune_send_pkts_in_cb(lune_socket_send_pkt_t *pkts,
    unsigned int pkt_num, unsigned int mode);

int lune_sendto_in_cb(const unsigned char *buf, unsigned int len,
    void *dst_addr, unsigned int dst_addr_len,
    void *arg, unsigned int arg_len);

int lune_close_in_cb(void);

int lune_get_socket_opt_in_cb(lune_socket_opt_en opt,
    unsigned char *opt_val, unsigned int opt_len);

int lune_set_socket_opt_in_cb(lune_socket_opt_en opt,
    const unsigned char *opt_val, unsigned int opt_len);

#ifdef __cplusplus
}
#endif

#endif