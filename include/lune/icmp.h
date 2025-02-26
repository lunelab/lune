/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2024 Lune Reseau, Inc.
 */

#ifndef __LUNE_ICMP_H__
#define __LUNE_ICMP_H__

#include "lune/id.h"
#include "lune/ip.h"

#ifdef __cplusplus
extern "C" {
#endif

#define LUNE_ICMP_HDR_LEN                   (sizeof(lune_icmp_hdr_t))
#define LUNE_ICMPV6_OPT_SLLA_LEN            (sizeof(lune_icmpv6_opt_slla_t))
#define LUNE_ICMPV6_OPT_TLLA_LEN            (sizeof(lune_icmpv6_opt_tlla_t))

#define LUNE_ICMPV4_ECHO_REPLY              0
#define LUNE_ICMPV4_DEST_UNREACHABLE        3
#define LUNE_ICMPV4_REDIRECT                5
#define LUNE_ICMPV4_ECHO_REQUEST            8

#define LUNE_ICMPV6_ECHO_REQUEST            128
#define LUNE_ICMPV6_ECHO_REPLY              129
#define LUNE_ICMPV6_NB_SOLICIT              135
#define LUNE_ICMPV6_NB_ADVERT               136

/* source link-layer address */
#define LUNE_ICMPV6_NB_SOLICIT_OPT_SLLA     1
/* target link-layer address */
#define LUNE_ICMPV6_NB_SOLICIT_OPT_TLLA     2

#define LUNE_ICMPV4_MAX_PAYLOAD_LEN         (LUNE_IPV4_MAX_PAYLOAD_LEN - LUNE_ICMP_HDR_LEN)
#define LUNE_ICMPV6_MAX_PAYLOAD_LEN         (LUNE_IPV6_MAX_PAYLOAD_LEN - LUNE_ICMP_HDR_LEN)

#pragma pack(1)
typedef struct _lune_icmp_hdr {
    unsigned char type;
    unsigned char code;
    unsigned short csum;
    union {
        struct {
            unsigned short id;
            unsigned short seq_no;
        };
        unsigned int data;
    };
} lune_icmp_hdr_t;

typedef struct _lune_icmpv6_opt_hdr {
    unsigned char type;
    unsigned char len;
    unsigned char val[0];
} lune_icmpv6_opt_hdr_t;

typedef struct _lune_icmpv6_opt_slla {
    unsigned char type;
    unsigned char len;
    lune_mac_addr_t src_mac;
} lune_icmpv6_opt_slla_t;

typedef struct _lune_icmpv6_opt_tlla {
    unsigned char type;
    unsigned char len;
    lune_mac_addr_t tgt_mac;
} lune_icmpv6_opt_tlla_t;
#pragma pack()

typedef struct _lune_icmp_sendto_arg {
    unsigned char type;
    unsigned char code;
    union {
        /*
            NOTICE:
            caller MUST guarantee id & seq_no fields passed to LUNE
            are network-order. the fields are defined ONLY to facilitate
            constructing icmp echo message
        */
        struct {
            unsigned short id;
            unsigned short seq_no;
        };
        unsigned int data;
    };
} lune_icmp_sendto_arg_t;

typedef void (*lune_icmp_socket_recvfrom_callback_func_t)(void *,
    const lune_ip_addr_t *, const unsigned char *, unsigned int);
typedef struct _lune_icmp_socket_callback {
    lune_icmp_socket_recvfrom_callback_func_t recvfrom;
    void *data;
} lune_icmp_socket_callback_t;

#ifdef __cplusplus
}
#endif

#endif