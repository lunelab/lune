/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2024 Lune Reseau, Inc.
 */

#ifndef __NET_IF_DPDK_H_PRE__
#define __NET_IF_DPDK_H_PRE__

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_version.h>

extern __thread struct rte_mempool *g_net_if_dpdk_send_mbuf_pool;

#endif

#ifndef __NET_IF_DPDK_H__
#define __NET_IF_DPDK_H__

#include "lune/net_if.h"
#include "lune/os/linux.h"

#include "utils/cap.h"
#include "utils/net_if_dpdk_cap.h"

#if RTE_VERSION >= RTE_VERSION_NUM(22, 11, 0, 0)

#define DEV_TX_OFFLOAD_IPV4_CKSUM               RTE_ETH_TX_OFFLOAD_IPV4_CKSUM
#define DEV_TX_OFFLOAD_UDP_CKSUM                RTE_ETH_TX_OFFLOAD_UDP_CKSUM
#define DEV_TX_OFFLOAD_TCP_CKSUM                RTE_ETH_TX_OFFLOAD_TCP_CKSUM

#define DEV_RX_OFFLOAD_IPV4_CKSUM               RTE_ETH_RX_OFFLOAD_IPV4_CKSUM
#define DEV_RX_OFFLOAD_UDP_CKSUM                RTE_ETH_RX_OFFLOAD_UDP_CKSUM
#define DEV_RX_OFFLOAD_TCP_CKSUM                RTE_ETH_RX_OFFLOAD_TCP_CKSUM

#define PKT_TX_IPV4                             RTE_MBUF_F_TX_IPV4

#define PKT_TX_IP_CKSUM                         RTE_MBUF_F_TX_IP_CKSUM
#define PKT_TX_TCP_CKSUM                        RTE_MBUF_F_TX_TCP_CKSUM
#define PKT_TX_UDP_CKSUM                        RTE_MBUF_F_TX_UDP_CKSUM

#define PKT_RX_IP_CKSUM_BAD                     RTE_MBUF_F_RX_IP_CKSUM_BAD
#define PKT_RX_L4_CKSUM_BAD                     RTE_MBUF_F_RX_L4_CKSUM_BAD

#define PKT_RX_IP_CKSUM_MASK                    RTE_MBUF_F_RX_IP_CKSUM_MASK
#define PKT_RX_L4_CKSUM_MASK                    RTE_MBUF_F_RX_L4_CKSUM_MASK

#define DEV_TX_OFFLOAD_MBUF_FAST_FREE           RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE

#define ETH_RSS_IP                              RTE_ETH_RSS_IP
#define ETH_RSS_L3_SRC_ONLY                     RTE_ETH_RSS_L3_SRC_ONLY
#define ETH_RSS_L3_DST_ONLY                     RTE_ETH_RSS_L3_DST_ONLY

#define ETH_MQ_RX_RSS                           RTE_ETH_MQ_RX_RSS

#endif

typedef struct _net_if_dpdk_net_if {
    char name[LUNE_MAX_SHORT_NAME_BUF_LEN];
    struct rte_eth_dev_info dev_info;
    struct rte_eth_conf port_conf;
    unsigned short rxd_num;
    unsigned short txd_num;
    unsigned short rxq_num;
    unsigned short txq_num;
    unsigned short port_id;
    unsigned short mtu;
#define NET_IF_DPDK_FLAG_ON(ifp, flag)          (((net_if_dpdk_net_if_t *)(ifp))->flags & (flag))
#define NET_IF_DPDK_SET_FLAG(ifp, flag)         \
    do { ((net_if_dpdk_net_if_t *)(ifp))->flags |= (flag); } while (0)
#define NET_IF_DPDK_CLEAR_FLAG(ifp, flag)       \
    do { ((net_if_dpdk_net_if_t *)(ifp))->flags &= (~flag); } while (0)
#define NET_IF_DPDK_FLAG_START                  0x0001
#define NET_IF_DPDK_IS_STARTED(ifp)             NET_IF_DPDK_FLAG_ON(ifp, NET_IF_DPDK_FLAG_START)
#define NET_IF_DPDK_SET_START(ifp)              NET_IF_DPDK_SET_FLAG(ifp, NET_IF_DPDK_FLAG_START)
#define NET_IF_DPDK_SET_STOP(ifp)               NET_IF_DPDK_CLEAR_FLAG(ifp, NET_IF_DPDK_FLAG_START)
#define NET_IF_DPDK_FLAG_DISTRIB                0x0002
#define NET_IF_DPDK_IS_DISTRIB_SET(ifp)         NET_IF_DPDK_FLAG_ON(ifp, NET_IF_DPDK_FLAG_DISTRIB)
#define NET_IF_DPDK_SET_DISTRIB(ifp)            NET_IF_DPDK_SET_FLAG(ifp, NET_IF_DPDK_FLAG_DISTRIB)
#define NET_IF_DPDK_CLEAR_DISTRIB(ifp)          NET_IF_DPDK_CLEAR_FLAG(ifp, NET_IF_DPDK_FLAG_DISTRIB)
    unsigned short flags;
#define NET_IF_DPDK_MAX_QUEUE_NUM               (16)
    unsigned short queue_cnt;
    unsigned short queue_enabled_cnt;
    lune_net_if_dpdk_rss_type_en rss_type;
    void *queue_array[NET_IF_DPDK_MAX_QUEUE_NUM];
    pthread_spinlock_t lock;
#define NET_IF_DPDK_IS_CAP_ENABLED(ifp)         (NULL != ((net_if_dpdk_net_if_t *)(ifp))->net_if_dpdk_cap)
#define NET_IF_DPDK_CAP_PKT_OUT(ifp, buf, len)  \
    do {                                        \
        if (NET_IF_DPDK_IS_CAP_ENABLED(ifp)) {  \
            net_if_dpdk_cap_cap_pkt(((net_if_dpdk_net_if_t *)(ifp))->net_if_dpdk_cap,   \
                (buf), (len), 0);               \
        }                                       \
    } while (0)
#define NET_IF_DPDK_CAP_MBUF_IN(ifp, mbuf)      \
    do {                                        \
        if (NET_IF_DPDK_IS_CAP_ENABLED(ifp)) {  \
            net_if_dpdk_cap_cap_mbuf(((net_if_dpdk_net_if_t *)(ifp))->net_if_dpdk_cap,  \
                (mbuf), 1);                     \
        }                                       \
    } while (0)
    void *net_if_dpdk_cap;
} net_if_dpdk_net_if_t;

extern pthread_spinlock_t g_net_if_dpdk_lock;

/*
    reuse the field for reference count of mbuf
*/
static inline void net_if_dpdk_mbuf_init_and_hold(struct rte_mbuf *mbuf)
{
    lune_atomic64_set((lune_atomic64_t *)&mbuf->ol_flags, 1);
}

static inline void net_if_dpdk_mbuf_hold(struct rte_mbuf *mbuf)
{
    lune_atomic64_inc((lune_atomic64_t *)&mbuf->ol_flags);
}

static inline void net_if_dpdk_mbuf_put(struct rte_mbuf *mbuf)
{
    if (lune_atomic64_dec_is_zero((lune_atomic64_t *)&mbuf->ol_flags)) {
        rte_pktmbuf_free(mbuf);
    }
}

int net_if_dpdk_is_valid_chan_type(void *dpdk, lune_net_if_type_en type);

net_if_dpdk_net_if_t *net_if_dpdk_add_dpdk_net_if(const char *name,
    unsigned short rxq_num,
    unsigned short txq_num,
    lune_net_if_dpdk_rss_type_en rss_type);
void net_if_dpdk_del_dpdk_net_if(net_if_dpdk_net_if_t *ifp);
net_if_dpdk_net_if_t *net_if_dpdk_get_dpdk_net_if_by_name(const char *name);

net_if_dpdk_net_if_t *net_if_dpdk_get_dpdk_net_if(void *dpdk);

int net_if_dpdk_init(void);
void net_if_dpdk_fini(void);

int net_if_dpdk_local_init(void);
void net_if_dpdk_local_fini(void);

#endif