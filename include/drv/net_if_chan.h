/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2024 Lune Reseau, Inc.
 */

#ifndef __NET_IF_CHAN_H__
#define __NET_IF_CHAN_H__

#include "drv/net_if.h"

extern net_if_drv_t g_net_if_drv_chan;

net_if_t *net_if_chan_get_aggr_ifp(net_if_t *ifp);

#endif