/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2024 Lune Reseau, Inc.
 */

#ifndef __NET_IF_DPDK_QUEUE_H__
#define __NET_IF_DPDK_QUEUE_H__

#include "lune/net_if.h"

#include "drv/dpdk/net_if_dpdk.h"
#include "drv/net_if.h"

extern net_if_drv_t g_net_if_drv_dpdk_queue;

int net_if_dpdk_queue_is_valid_chan_type(void *queue, lune_net_if_type_en type);
int net_if_dpdk_queue_is_valid_chan_num(void *queue, unsigned int chan_num);
unsigned int net_if_dpdk_queue_get_queue_id(void *queue);
unsigned int net_if_dpdk_queue_get_queue_num(void *queue);
net_if_dpdk_net_if_t *net_if_dpdk_queue_get_dpdk_net_if(void *queue);

#endif