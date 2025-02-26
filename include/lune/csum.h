/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2024 Lune Reseau, Inc.
 */

#ifndef __LUNE_CSUM_H__
#define __LUNE_CSUM_H__

#include "lune/ipv4.h"

unsigned short lune_calc_ipv4_csum(void *hdr, unsigned short hdr_len);

unsigned short lune_calc_l4_csum(void *hdr,
    lune_ipv4_addr_t src_addr, 
    lune_ipv4_addr_t dst_addr, 
    unsigned short l4_len,
    unsigned char proto);

#endif