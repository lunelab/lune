/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2024 Lune Reseau, Inc.
 */

#ifndef __COMMON_H__
#define __COMMON_H__

#include "lune/assert.h"
#include "lune/id.h"

#include "drv/net_if.h"
#include "net/ip.h"
#include "net/mac.h"

#define ID_MAX_NUM_OF_ID_IN_BIT     (25)

static inline unsigned int lower_entry_get_id(void *lower_entry, lune_id_type_en lower_type)
{
    switch (lower_type) {
    case LUNE_ID_NET_IF:
        return ((net_if_t *)lower_entry)->id;
    case LUNE_ID_MAC:
        return ((mac_t *)lower_entry)->id;
    case LUNE_ID_IPV4:
    case LUNE_ID_IPV6:
        return ((ip_t *)lower_entry)->id;
    default:
        lune_assert(0);
        return LUNE_INVALID_ID;
    }
}

#ifdef LUNE_BUILD_DPDK
static inline int lower_entry_is_dpdk(void *lower_entry, lune_id_type_en lower_type)
{
    switch (lower_type) {
    case LUNE_ID_NET_IF:
        return NET_IF_IS_DPDK((net_if_t *)lower_entry);
    case LUNE_ID_MAC:
        return MAC_IS_DPDK((mac_t *)lower_entry);
    case LUNE_ID_IPV4:
    case LUNE_ID_IPV6:
        return IP_IS_DPDK((ip_t *)lower_entry);
    default:
        lune_assert(0);
        return 0;
    }
}
#else
#define lower_entry_is_dpdk         (0)
#endif

static inline void lower_entry_hold(void *lower_entry, lune_id_type_en lower_type)
{
    switch (lower_type) {
    case LUNE_ID_NET_IF:
        net_if_hold(lower_entry);
        break;
    case LUNE_ID_MAC:
        mac_hold(lower_entry);
        break;
    case LUNE_ID_IPV4:
    case LUNE_ID_IPV6:
        ip_hold(lower_entry);
        break;
    default:
        lune_assert(0);
        break;
    }
}

static inline void lower_entry_put(void *lower_entry, lune_id_type_en lower_type)
{
    switch (lower_type) {
    case LUNE_ID_NET_IF:
        net_if_put(lower_entry);
        break;
    case LUNE_ID_MAC:
        mac_put(lower_entry);
        break;
    case LUNE_ID_IPV4:
    case LUNE_ID_IPV6:
        ip_put(lower_entry);
        break;
    default:
        lune_assert(0);
        break;
    }
}

#endif