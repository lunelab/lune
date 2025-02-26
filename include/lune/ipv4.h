/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2024 Lune Reseau, Inc.
 */

#ifndef __LUNE_IPV4_H__
#define __LUNE_IPV4_H__

#include "lune/id.h"

#ifdef __cplusplus
extern "C" {
#endif

#define LUNE_IPV4_ADDR_LEN          (sizeof(lune_ipv4_addr_t))
#define LUNE_IPV4_HDR_LEN           (sizeof(lune_ipv4_hdr_t))
/* string lengths include trailing '0' */
#define LUNE_IPV4_MAX_ADDR_STR_LEN  (16)
#define LUNE_IPV4_MIN_ADDR_STR_LEN  (8)

/* ipv4 flags */
#define LUNE_IPV4_FLAG_CE           0x8000  /* congestion */
#define LUNE_IPV4_FLAG_DF           0x4000  /* don't fragment */
#define LUNE_IPV4_FLAG_MF           0x2000  /* more fragments */
#define LUNE_IPV4_FRAG_OFFSET       0x1fff  /* fragment offset */

#define LUNE_IPV4_MAX_PAYLOAD_LEN   (65535 - LUNE_IPV4_HDR_LEN)

#define LUNE_BROADCAST_IPV4         (0xffffffff)

typedef unsigned int lune_ipv4_addr_t;

#pragma pack(1)
typedef struct _lune_ipv4_hdr {
    unsigned char ver_len;
    unsigned char tos;
    unsigned short total_len;
    unsigned short id;
    unsigned short offset;
    unsigned char ttl;
    unsigned char proto;
    unsigned short csum;
    lune_ipv4_addr_t src_addr;
    lune_ipv4_addr_t dst_addr;
} lune_ipv4_hdr_t;

typedef struct _lune_ipv4_max_hdr {
    lune_ipv4_hdr_t hdr;
    unsigned char opt[40];
} lune_ipv4_max_hdr_t;

/* pseudo header */
typedef struct _lune_ipv4_psd_hdr {
    lune_ipv4_addr_t src_addr;
    lune_ipv4_addr_t dst_addr;
    unsigned char z;
    unsigned char proto;
    unsigned short len;
} lune_ipv4_psd_hdr_t;
#pragma pack()

typedef struct _lune_ipv4_sendto_arg {
    unsigned char tos;
    unsigned short total_len;
    unsigned short id;
    unsigned short offset;
    unsigned char ttl;
    unsigned char proto;
    unsigned char opt_len;
} lune_ipv4_sendto_arg_t;

int lune_str_to_ipv4(const char *str, lune_ipv4_addr_t *addr);
char *lune_ipv4_to_str(const lune_ipv4_addr_t addr, char *buf, unsigned int len);

unsigned int lune_add_ipv4(lune_ipv4_addr_t ipv4, lune_ipv4_addr_t mask,
    lune_ipv4_addr_t gw, lune_id_type_en sub_type, unsigned int sub_id);
int lune_del_ipv4(unsigned int id);
int lune_get_ipv4(lune_ipv4_addr_t ipv4,
    lune_id_type_en sub_type, unsigned int sub_id, unsigned int *ip_id);

#ifdef __cplusplus
}
#endif

#endif