/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2024 Lune Reseau, Inc.
 */

#ifndef __LUNE_IP_H__
#define __LUNE_IP_H__

#include "lune/id.h"
#include "lune/ipv4.h"
#include "lune/ipv6.h"
#include "lune/net.h"

#ifdef __cplusplus
extern "C" {
#endif

#define LUNE_IP_PROTO_ICMPV4        (1)
#define LUNE_IP_PROTO_IGMP          (2)
#define LUNE_IP_PROTO_IP            (4)
#define LUNE_IP_PROTO_TCP           (6)
#define LUNE_IP_PROTO_UDP           (17)
#define LUNE_IP_PROTO_IPV6_FRAG     (44)
#define LUNE_IP_PROTO_GRE           (47)
#define LUNE_IP_PROTO_ICMPV6        (58)
#define LUNE_IP_PROTO_IPV6_NO_NEXT  (59)

#define LUNE_IP_MAX_ADDR_STR_LEN    LUNE_IPV6_MAX_ADDR_STR_LEN

#define LUNE_IP_INIT(ip)                                            \
    do {                                                            \
        ((lune_ip_addr_t *)ip)->is_ipv6 = 0;                        \
        ((lune_ip_addr_t *)ip)->ipv4 = 0;                           \
    } while (0)

#define LUNE_IP_CPY(dst_ip, src_ip)                                 \
    do {                                                            \
        ((lune_ip_addr_t *)dst_ip)->is_ipv6                         \
            = ((const lune_ip_addr_t *)src_ip)->is_ipv6;            \
        if (((lune_ip_addr_t *)dst_ip)->is_ipv6) {                  \
            *(unsigned long long *)&((lune_ip_addr_t *)dst_ip)->ipv6.addr[0]                        \
                = *(const unsigned long long *)&((const lune_ip_addr_t *)src_ip)->ipv6.addr[0];     \
            *(unsigned long long *)&((lune_ip_addr_t *)dst_ip)->ipv6.addr[2]                        \
                = *(const unsigned long long *)&((const lune_ip_addr_t *)src_ip)->ipv6.addr[2];     \
        } else {                                                    \
            ((lune_ip_addr_t *)dst_ip)->ipv4                        \
                = ((const lune_ip_addr_t *)src_ip)->ipv4;           \
        }                                                           \
    } while (0)

/*
    for ipv6 address:
    1. compare first int
    2. compare second int
    3. compare third & last int (unsigned long long)
*/
#define LUNE_IP_CMP(ip1, ip2)                                       \
    (!((((lune_ip_addr_t *)ip1)->ipv4 == ((lune_ip_addr_t *)ip2)->ipv4)         \
    && (((lune_ip_addr_t *)ip1)->is_ipv6 == ((lune_ip_addr_t *)ip2)->is_ipv6)   \
    && ((!((lune_ip_addr_t *)ip1)->is_ipv6)                         \
    || (((lune_ip_addr_t *)ip1)->ipv6.addr[1]                       \
    == ((lune_ip_addr_t *)ip2)->ipv6.addr[1]                        \
    && (*(unsigned long long *)&((lune_ip_addr_t *)ip1)->ipv6.addr[2]           \
    == *(unsigned long long *)&((lune_ip_addr_t *)ip2)->ipv6.addr[2])))))

#define LUNE_IP_GT(ip1, ip2)                                        \
    ((lune_ip_addr_t *)ip1)->is_ipv6                                \
    ? ((lune_ntohl(((lune_ip_addr_t *)ip1)->ipv6.addr[0])           \
    > lune_ntohl(((lune_ip_addr_t *)ip2)->ipv6.addr[0]))            \
    || ((((lune_ip_addr_t *)ip1)->ipv6.addr[0]                      \
    == ((lune_ip_addr_t *)ip2)->ipv6.addr[0])                       \
    && ((lune_ntohl(((lune_ip_addr_t *)ip1)->ipv6.addr[1])          \
    > lune_ntohl(((lune_ip_addr_t *)ip2)->ipv6.addr[1]))))          \
    || ((((lune_ip_addr_t *)ip1)->ipv6.addr[1]                      \
    == ((lune_ip_addr_t *)ip2)->ipv6.addr[1])                       \
    && ((lune_ntohl(((lune_ip_addr_t *)ip1)->ipv6.addr[2])          \
    > lune_ntohl(((lune_ip_addr_t *)ip2)->ipv6.addr[2]))))          \
    || ((((lune_ip_addr_t *)ip1)->ipv6.addr[2]                      \
    == ((lune_ip_addr_t *)ip2)->ipv6.addr[2])                       \
    && ((lune_ntohl(((lune_ip_addr_t *)ip1)->ipv6.addr[3])          \
    > lune_ntohl(((lune_ip_addr_t *)ip2)->ipv6.addr[3])))))         \
    : ((lune_ip_addr_t *)ip1)->ipv4 > ((lune_ip_addr_t *)ip2)->ipv4

/* get little-end integer converted from ip address */
#define LUNE_IP_GET_LE_INT(ip)                                      \
    (((lune_ip_addr_t *)ip)->is_ipv6                                \
    ? lune_ntohl(((lune_ip_addr_t *)ip)->ipv6.addr[3])             \
    : ((lune_ip_addr_t *)ip)->ipv4)

typedef enum _lune_ip_opt {
    /* get options */
    LUNE_IP_OPT_GET_STATS = 0,
    LUNE_IP_OPT_GET_SUB_INFO,
    LUNE_IP_OPT_GET_ADDR,
    LUNE_IP_OPT_GET_SOCKET_ID,
    /* set options */
    LUNE_IP_OPT_ADD_MEMBERSHIP = 256,
    LUNE_IP_OPT_DROP_MEMBERSHIP,
    LUNE_IP_OPT_DISABLE_ARP,
    LUNE_IP_OPT_ENABLE_ARP,
} lune_ip_opt_en;

typedef struct _lune_ip_stats {
    unsigned long long pkt_in;
    unsigned long long pkt_out;
    unsigned long long byte_in;
    unsigned long long byte_out;
} lune_ip_stats_t;

typedef struct _lune_ip_sub_info {
    unsigned int id;
    lune_id_type_en type;
} lune_ip_sub_info_t;

#pragma pack(8)
typedef struct _lune_ip_addr {
    union {
        lune_ipv4_addr_t ipv4;
        lune_ipv6_addr_t ipv6;
    };
    unsigned int is_ipv6;
    unsigned int rsvd;
} lune_ip_addr_t;
#pragma pack()

/*
    callback function for ip datagram socket with the following arguments

    void *
        callback data by user
    const lune_ip_addr_t *
        source address of receiving ip packet (reassembled if fragmented)
    unsigned char
        protocol field in ipv4 header or next header field in ipv6 header
    const unsigned char *
        pointer to payload of ipv4/ipv6 packet
    unsigned int
        payload length
*/
typedef void (*lune_ip_socket_recvfrom_callback_func_t)(void *,
    const lune_ip_addr_t *, unsigned char, const unsigned char *, unsigned int);
typedef struct _lune_ip_socket_callback {
    lune_ip_socket_recvfrom_callback_func_t recvfrom;
    void *data;
} lune_ip_socket_callback_t;

/*
    callback function for ipv4 raw socket with the following arguments

    void *
        callback data by user
    const unsigned char *
        pointer to ipv4 header
    unsigned int
        length of ipv4 header and payload
*/
typedef void (*lune_ipv4_socket_recv_callback_func_t)(void *,
    const unsigned char *, unsigned int);
typedef struct _lune_ipv4_socket_callback {
    lune_ipv4_socket_recv_callback_func_t recv;
    void *data;
} lune_ipv4_socket_callback_t;

/*
    callback function for ipv6 raw socket with the following arguments

    void *
        callback data by user
    const unsigned char *
        pointer to ipv6 header
    unsigned int
        length of ipv6 header and payload
*/
typedef void (*lune_ipv6_socket_recv_callback_func_t)(void *,
    const unsigned char *, unsigned int);
typedef struct _lune_ipv6_socket_callback {
    lune_ipv6_socket_recv_callback_func_t recv;
    void *data;
} lune_ipv6_socket_callback_t;

typedef struct _lune_ip_sendto_arg {
    unsigned char proto;
} lune_ip_sendto_arg_t;

int lune_get_ip_opt(unsigned int id,
    lune_ip_opt_en opt, void *opt_val, unsigned int opt_len);
int lune_set_ip_opt(unsigned int id,
    lune_ip_opt_en opt, const void *opt_val, unsigned int opt_len);

#ifdef __cplusplus
}
#endif

#endif