/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2024 Lune Reseau, Inc.
 */

#ifndef __LUNE_IGMP_H__
#define __LUNE_IGMP_H__

#include "lune/id.h"
#include "lune/ipv4.h"

#ifdef __cplusplus
extern "C" {
#endif

#define LUNE_IGMP_HDR_LEN           (sizeof(lune_igmp_hdr_t))

typedef enum _lune_igmp_version {
    LUNE_IGMP_VERSION_1 = 0,
    LUNE_IGMP_VERSION_2,
    LUNE_IGMP_VERSION_3,
    LUNE_IGMP_VERSION_MAX,
} lune_igmp_version_en;

#define LUNE_IGMP_MAX_PAYLOAD_LEN   (LUNE_IPV4_MAX_PAYLOAD_LEN - LUNE_IGMP_HDR_LEN)

#pragma pack(1)
typedef struct _lune_igmp_hdr {
    unsigned char type;
    unsigned char mrt;  /* maximum response time by unit 0.1s */
    unsigned short csum;
    lune_ipv4_addr_t group_addr;
} lune_igmp_hdr_t;
#pragma pack()

typedef struct _lune_ipv4_join_group_arg {
    lune_ipv4_addr_t group_addr;
    lune_igmp_version_en igmp_ver;
} lune_ipv4_join_group_arg_t;

typedef struct _lune_igmp_sendto_arg {
    unsigned char type;
    unsigned char mrt;
    lune_ipv4_addr_t group_addr;
} lune_igmp_sendto_arg_t;

typedef void (*lune_igmp_socket_recvfrom_callback_func_t)(void *, 
    lune_ipv4_addr_t, const unsigned char *, unsigned int);
typedef struct _lune_igmp_socket_callback {
    lune_igmp_socket_recvfrom_callback_func_t recvfrom;
    void *data;
} lune_igmp_socket_callback_t;

#ifdef __cplusplus
}
#endif

#endif