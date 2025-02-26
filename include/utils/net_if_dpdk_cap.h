/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2024 Lune Reseau, Inc.
 */

#ifndef __NET_IF_DPDK_CAP_H__
#define __NET_IF_DPDK_CAP_H__

#include <rte_mbuf.h>

#include "lune/atomic.h"
#include "lune/os/linux.h"
#ifdef LUNE_DEBUG
#include "lune/timer.h"
#endif

#include "kernel/time.h"

#define NET_IF_DPDK_CAP_INIT_LIST(list)                    \
    do {                                                \
        ((net_if_dpdk_cap_pkt_list_t *)list)->next = NULL; \
        ((net_if_dpdk_cap_pkt_list_t *)list)->type = NET_IF_DPDK_CAP_NODE_TYPE_NONE;      \
        ((net_if_dpdk_cap_pkt_list_t *)list)->len = 0;     \
    } while (0)

#pragma pack(8)
typedef struct _net_if_dpdk_cap_pkt {
    struct _net_if_dpdk_cap_pkt *next;
#define NET_IF_DPDK_CAP_NODE_TYPE_NONE         (0)
#define NET_IF_DPDK_CAP_NODE_TYPE_PKT          (1)
#define NET_IF_DPDK_CAP_NODE_TYPE_MBUF         (2)
    unsigned int type;
    unsigned short len;
    unsigned short is_in;
    lune_time_val_t tv;
    unsigned char val[0];
} net_if_dpdk_cap_pkt_t;
#pragma pack()

typedef net_if_dpdk_cap_pkt_t net_if_dpdk_cap_pkt_list_t;

typedef struct _net_if_dpdk_cap_stats {
    lune_atomic64_t cached_pkt_in;
    lune_atomic64_t cached_pkt_out;
    lune_atomic64_t cached_byte_in;
    lune_atomic64_t cached_byte_out;
    unsigned long long written_pkt_in;
    unsigned long long written_pkt_out;
    unsigned long long written_byte_in;
    unsigned long long written_byte_out;
} net_if_dpdk_cap_stats_t;

typedef struct _net_if_dpdk_cap {
    char name[LUNE_MAX_SHORT_NAME_BUF_LEN];
    void *cap_fp;
    void *cap_thd;                          /* unused for now */
    lune_atomic32_t ref_cnt;
#define NET_IF_DPDK_CAP_FLAG_ON(cap, flag)     (((net_if_dpdk_cap_t *)(cap))->flags & (flag))
#define NET_IF_DPDK_CAP_SET_FLAG(cap, flag)    \
    do { ((net_if_dpdk_cap_t *)(cap))->flags |= (flag); } while (0)
#define NET_IF_DPDK_CAP_CLEAR_FLAG(cap, flag)  \
    do { ((net_if_dpdk_cap_t *)(cap))->flags &= (~flag); } while (0)
#define NET_IF_DPDK_CAP_FLAG_STOP              0x00000001
#define NET_IF_DPDK_CAP_IS_STOPPED(cap)        NET_IF_DPDK_CAP_FLAG_ON(cap, NET_IF_DPDK_CAP_FLAG_STOP)
#define NET_IF_DPDK_CAP_SET_STOP(cap)          NET_IF_DPDK_CAP_SET_FLAG(cap, NET_IF_DPDK_CAP_FLAG_STOP)
#define NET_IF_DPDK_CAP_SET_START(cap)         NET_IF_DPDK_CAP_CLEAR_FLAG(cap, NET_IF_DPDK_CAP_FLAG_STOP)
#define NET_IF_DPDK_CAP_FLAG_REACH_LIMIT       0x00000002
#define NET_IF_DPDK_CAP_REACH_LIMIT(cap)       NET_IF_DPDK_CAP_FLAG_ON(cap, NET_IF_DPDK_CAP_FLAG_REACH_LIMIT)
#define NET_IF_DPDK_CAP_SET_REACH_LIMIT(cap)   NET_IF_DPDK_CAP_SET_FLAG(cap, NET_IF_DPDK_CAP_FLAG_REACH_LIMIT)
#define NET_IF_DPDK_CAP_CLEAR_REACH_LIMIT(cap) NET_IF_DPDK_CAP_CLEAR_FLAG(cap, NET_IF_DPDK_CAP_FLAG_REACH_LIMIT)
    unsigned int flags;
    net_if_dpdk_cap_pkt_list_t pkt_list;
    net_if_dpdk_cap_pkt_t *curr_pkt;
    net_if_dpdk_cap_pkt_t *last_pkt;
#define NET_IF_DPDK_CAP_INC_CACHED_PKT_IN(cap)             \
    do { lune_atomic64_inc(&((net_if_dpdk_cap_t *)cap)->stats.cached_pkt_in); } while (0)
#define NET_IF_DPDK_CAP_INC_CACHED_PKT_OUT(cap)            \
    do { lune_atomic64_inc(&((net_if_dpdk_cap_t *)cap)->stats.cached_pkt_out); } while (0)
#define NET_IF_DPDK_CAP_ADD_CACHED_BYTE_IN(cap, bytes)     \
    do { lune_atomic64_add(&((net_if_dpdk_cap_t *)cap)->stats.cached_byte_in, (bytes)); } while (0)
#define NET_IF_DPDK_CAP_ADD_CACHED_BYTE_OUT(cap, bytes)    \
    do { lune_atomic64_add(&((net_if_dpdk_cap_t *)cap)->stats.cached_byte_out, (bytes)); } while (0)
#define NET_IF_DPDK_CAP_DEC_CACHED_PKT_IN(cap)             \
    do { lune_atomic64_dec(&((net_if_dpdk_cap_t *)cap)->stats.cached_pkt_in); } while (0)
#define NET_IF_DPDK_CAP_DEC_CACHED_PKT_OUT(cap)            \
    do { lune_atomic64_dec(&((net_if_dpdk_cap_t *)cap)->stats.cached_pkt_out); } while (0)
#define NET_IF_DPDK_CAP_SUB_CACHED_BYTE_IN(cap, bytes)     \
    do { lune_atomic64_sub(&((net_if_dpdk_cap_t *)cap)->stats.cached_byte_in, (bytes)); } while (0)
#define NET_IF_DPDK_CAP_SUB_CACHED_BYTE_OUT(cap, bytes)    \
    do { lune_atomic64_sub(&((net_if_dpdk_cap_t *)cap)->stats.cached_byte_out, (bytes)); } while (0)
#define NET_IF_DPDK_CAP_INC_WRITTEN_PKT_IN(cap)            \
    do { ((net_if_dpdk_cap_t *)cap)->stats.written_pkt_in++; } while (0)
#define NET_IF_DPDK_CAP_INC_WRITTEN_PKT_OUT(cap)           \
    do { ((net_if_dpdk_cap_t *)cap)->stats.written_pkt_out++; } while (0)
#define NET_IF_DPDK_CAP_ADD_WRITTEN_BYTE_IN(cap, bytes)    \
    do { ((net_if_dpdk_cap_t *)cap)->stats.written_byte_in += (bytes); } while (0)
#define NET_IF_DPDK_CAP_ADD_WRITTEN_BYTE_OUT(cap, bytes)   \
    do { ((net_if_dpdk_cap_t *)cap)->stats.written_byte_out += (bytes); } while (0)
    net_if_dpdk_cap_stats_t stats;
#ifdef LUNE_DEBUG
    lune_nrt_timer_t stats_tmr;
#endif
} net_if_dpdk_cap_t;

void net_if_dpdk_cap_cap_pkt(void *cap,
    const unsigned char *buf, unsigned int len, unsigned int is_in);
void net_if_dpdk_cap_cap_mbuf(void *cap, struct rte_mbuf *mbuf, unsigned int is_in);

void *net_if_dpdk_cap_start(const char *net_if_name, const char *file_name);
void net_if_dpdk_cap_stop(void *cap);

#endif