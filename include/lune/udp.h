/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2024 Lune Reseau, Inc.
 */

#ifndef __LUNE_UDP_H__
#define __LUNE_UDP_H__

#include "lune/id.h"
#include "lune/ip.h"

#ifdef __cplusplus
extern "C" {
#endif

#define LUNE_UDP_HDR_LEN            (sizeof(lune_udp_hdr_t))

#define LUNE_UDP_MAX_PAYLOAD_LEN    (LUNE_IPV4_MAX_PAYLOAD_LEN - LUNE_UDP_HDR_LEN)
#define LUNE_UDPV6_MAX_PAYLOAD_LEN  (LUNE_IPV6_MAX_PAYLOAD_LEN - LUNE_UDP_HDR_LEN)

#pragma pack(1)
typedef struct _lune_udp_hdr {
    unsigned short src_port;
    unsigned short dst_port;
    unsigned short len;
    unsigned short csum;
} lune_udp_hdr_t;
#pragma pack()

typedef void (*lune_udp_socket_recvfrom_callback_func_t)(void *, 
    lune_socket_addr_t *, const unsigned char *, unsigned int);
typedef struct _lune_udp_socket_callback {
    lune_udp_socket_recvfrom_callback_func_t recvfrom;
    void *data;
} lune_udp_socket_callback_t;

#ifdef __cplusplus
}
#endif

#endif