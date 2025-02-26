/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2024 Lune Reseau, Inc.
 */

#ifndef __LUNE_NB_H__
#define __LUNE_NB_H__

#include "lune/common.h"
#include "lune/ip.h"
#include "lune/mac.h"

#ifdef __cplusplus
extern "C" {
#endif

int lune_resolve_mac(unsigned int ip_id, const lune_ip_addr_t *dst_addr);
int lune_get_resolved_mac(const lune_ip_addr_t *dst_addr, lune_mac_addr_t dst_mac, unsigned int net_if_id);

#ifdef __cplusplus
}
#endif

#endif