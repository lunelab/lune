/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2024 Lune Reseau, Inc.
 */

#ifndef __LUNE_ARP_H__
#define __LUNE_ARP_H__

#include "lune/mac.h"
#include "lune/ipv4.h"
#include "lune/net.h"

#ifdef __cplusplus
extern "C" {
#endif

#define LUNE_ARP_REQ            0x0001
#define LUNE_ARP_RESP           0x0002

#define LUNE_ARP_HDR_LEN        sizeof(lune_arp_hdr_t)

#define LUNE_HW_TYPE_ETHERNET   0x0001

#pragma pack(1)
typedef struct _lune_arp_hdr {
    unsigned short hard_type;
    unsigned short proto;
    unsigned char mac_len;
    unsigned char ipv4_len;
    unsigned short op_code;
    lune_mac_addr_t src_mac;
    unsigned int src_addr;
    lune_mac_addr_t dst_mac;
    unsigned int dst_addr;
} lune_arp_hdr_t;
#pragma pack()

int lune_send_grat_arp(unsigned int ip_id);

#ifdef __cplusplus
}
#endif

#endif