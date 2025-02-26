/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2024 Lune Reseau, Inc.
 */

#ifndef __ID_H__
#define __ID_H__

#include "lune/id.h"

#include "drv/net_if.h"
#include "net/ip.h"
#include "net/mac.h"
#include "net/socket.h"

static void *id_get_entry(lune_id_type_en type, unsigned int id)
{
    lune_assert(LUNE_INVALID_ID != id);

    switch (type) {
    case LUNE_ID_NET_IF:
        return (void *)net_if_get_net_if_by_id(id);
    case LUNE_ID_MAC:
        return (void *)mac_get_mac(id);
    case LUNE_ID_IPV4:
        return (void *)ip_get_ip_by_id(id);
    case LUNE_ID_SOCKET:
        return (void *)socket_get(id);
    default:
        lune_assert(0);
        return NULL;
    }
}

#endif