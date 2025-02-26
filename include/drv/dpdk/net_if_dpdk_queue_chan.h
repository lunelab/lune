/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2024 Lune Reseau, Inc.
 */

#ifndef __NBT_IF_DPDK_QUEUE_CHAN_H__
#define __NBT_IF_DPDK_QUEUE_CHAN_H__

#include "drv/net_if.h"

extern net_if_drv_t g_net_if_drv_dpdk_queue_chan;

int net_if_dpdk_queue_chan_recv_from_queue(net_if_t *ifp,
    struct rte_mbuf *mbuf, unsigned int chan_idx, unsigned int queue_idx);

#endif