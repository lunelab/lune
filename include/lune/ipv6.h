/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2024 Lune Reseau, Inc.
 */

#ifndef __LUNE_IPV6_H__
#define __LUNE_IPV6_H__

#include "lune/id.h"

#define LUNE_IPV6_ADDR_LEN                  (sizeof(lune_ipv6_addr_t))
#define LUNE_IPV6_HDR_LEN                   (sizeof(lune_ipv6_hdr_t))
#define LUNE_IPV6_FRAG_HDR_LEN              (sizeof(lune_ipv6_frag_hdr_t))
#define LUNE_IPV6_MAX_FLOW_LABEL            (0xfffff)
/* string lengths include trailing '0' */
#define LUNE_IPV6_MAX_ADDR_STR_LEN          (40)

#define LUNE_IPV6_FRAG_OFFSET               0xfff8
#define LUNE_IPV6_FRAG_MF                   0x0001

#define LUNE_IPV6_MIN_MTU                   (1280)

#define LUNE_IPV6_MAX_PAYLOAD_LEN           (65535)

#define LUNE_IPV6_CMP(ipv6p1, ipv6p2)       \
    (!(*(const unsigned long long *)(ipv6p1) == *(const unsigned long long *)(ipv6p2)   \
    && *((const unsigned long long *)(ipv6p1) + 1) == *((const unsigned long long *)(ipv6p2) + 1)))

#define LUNE_IPV6_CPY(dst, src)             \
    do {                                    \
        *(unsigned long long *)(dst) = *(const unsigned long long *)(src);              \
        *((unsigned long long *)(dst) + 1) = *((const unsigned long long *)(src) + 1);  \
    } while (0)

#define LUNE_IPV6_FRAG_HDR_CPY(dst, src)    \
    do {                                    \
        ((lune_ipv6_frag_hdr_t *)dst)->data = ((const lune_ipv6_frag_hdr_t *)src)->data;\
    } while (0)

typedef struct {
    union {
        /* store in network order for fast processing */
        unsigned int addr[4];
        unsigned char octet[16];
    };
} lune_ipv6_addr_t;

#pragma pack(1)
typedef struct _lune_ipv6_hdr {
    /* version / traffic class / flow label */
    unsigned int ver_tc_fl;
    unsigned short payload_len;
    unsigned char next_hdr;
    unsigned char hop_limit;
    lune_ipv6_addr_t src_addr;
    lune_ipv6_addr_t dst_addr;
} lune_ipv6_hdr_t;

typedef struct _lune_ipv6_max_hdr {
    lune_ipv6_hdr_t hdr;
    unsigned char opt[20];
} lune_ipv6_max_hdr_t;

typedef struct _lune_ipv6_frag_hdr {
    union {
        struct {
            unsigned char next_hdr;
            unsigned char rsvd;
            unsigned short offset;
            unsigned int id;
        };
        unsigned long long data;
    };
} lune_ipv6_frag_hdr_t;

/* pseudo header */
typedef struct _lune_ipv6_psd_hdr {
    lune_ipv6_addr_t src_addr;
    lune_ipv6_addr_t dst_addr;
    unsigned int len;
    unsigned char zeros[3];
    unsigned char proto;
} lune_ipv6_psd_hdr_t;

#pragma pack()

typedef struct _lune_ipv6_sendto_arg {
    unsigned char trf_class;
    unsigned int flow_label;
    unsigned short payload_len;
    unsigned char next_hdr;
    unsigned char hop_limit;
} lune_ipv6_sendto_arg_t;

int lune_str_to_ipv6(const char *str, lune_ipv6_addr_t *addr);
char *lune_ipv6_to_str(const lune_ipv6_addr_t *addr, char *buf, unsigned int len);

unsigned int lune_add_ipv6(lune_ipv6_addr_t *ipv6,
    lune_id_type_en sub_type, unsigned int sub_id);
int lune_del_ipv6(unsigned int id);
int lune_get_ipv6(lune_ipv6_addr_t *ipv6,
    lune_id_type_en sub_type, unsigned int sub_id, unsigned int *ip_id);

#endif