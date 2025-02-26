/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2024 Lune Reseau, Inc.
 */

#include "lune/log.h"
#include "lune/mem.h"
#include "lune/net_if.h"
#include "lune/os/linux.h"
#include "lune/time.h"
#include "lune/timer.h"

#include "drv/aggr.h"
#include "drv/dpdk/net_if_dpdk.h"
#include "drv/net_if.h"
#include "kernel/sched.h"
#include "net/socket.h"
#include "rt/core.h"
#include "utils/net_if_dpdk_cap.h"

#define NET_IF_DPDK_RX_RING_SIZE               (1024)
#define NET_IF_DPDK_TX_RING_SIZE               (1024)

#define NET_IF_DPDK_DEFAULT_TXQ_NUM            (1)

#define NET_IF_DPDK_MAX_RECV_PKTS_ATTEMPTS     (10)

#define NET_IF_DPDK_MAX_NET_IF_NUM                (16)

/*
    3 interface topologies is supported by dpdk driver:
    1. Non-aggregated interface
    2. Aggregated interface aggregating LUNE_NET_IF_DPDK_CHAN interfaces
    3. Aggregated interface aggregating LUNE_NET_IF_CHAN interfaces only if 2 not
       available (e.g., limit of tx queue)
*/

typedef struct _net_if_dpdk {
    net_if_dpdk_net_if_t *ifp;
    unsigned short rx_num;
    unsigned short rx_offset;
    unsigned short tx_offset;
#define NET_IF_DPDK_FLAG_UP            0x00000001
#define NET_IF_DPDK_IS_UP(dpdk)        \
    (((net_if_dpdk_t *)(dpdk))->flags & NET_IF_DPDK_FLAG_UP)
#define NET_IF_DPDK_SET_UP(dpdk)       do { ((net_if_dpdk_t *)(dpdk))->flags =    \
    (((net_if_dpdk_t *)(dpdk))->flags | (NET_IF_DPDK_FLAG_UP)); } while (0)
#define NET_IF_DPDK_SET_DOWN(dpdk)     do { ((net_if_dpdk_t *)(dpdk))->flags =    \
    (((net_if_dpdk_t *)(dpdk))->flags & (~NET_IF_DPDK_FLAG_UP)); } while (0)
    unsigned short flags;
    unsigned int tx_task_id;
#define NET_IF_DPDK_MAX_RX_PKT_BURST   (32)
    struct rte_mbuf *rx_pkts_burst[NET_IF_DPDK_MAX_RX_PKT_BURST];
#define NET_IF_DPDK_MAX_TX_PKT_BURST   (32)
    struct rte_mbuf *tx_pkts_burst[NET_IF_DPDK_MAX_TX_PKT_BURST];
    unsigned long long pkt_in_ipv4_csum_err;
    unsigned long long pkt_in_l4_csum_err;
    net_if_t *qifp;
} net_if_dpdk_t;

extern net_if_drv_t g_net_if_drv_dpdk;

/*
    according to rte_pktmbuf_pool_create:

    The optimum size (in terms of memory usage) for a mempool is
    when n is a power of two minus one: n = (2^q - 1).
*/
#define NET_IF_DPDK_MBUF_NUM   (1024 * 256 - 1)
__thread struct rte_mempool *g_net_if_dpdk_send_mbuf_pool = (void *)-1;

pthread_spinlock_t g_net_if_dpdk_lock;
static unsigned int s_net_if_dpdk_cnt;
static net_if_dpdk_net_if_t *s_net_if_dpdk_array[NET_IF_DPDK_MAX_NET_IF_NUM];

static const struct rte_eth_conf s_dpdk_default_port_conf = {
    .rxmode = {
#if RTE_VERSION < RTE_VERSION_NUM(21, 11, 0, 0)
        .max_rx_pkt_len = RTE_ETHER_MAX_LEN,
#endif
    },
};

static int net_if_dpdk_configure(net_if_dpdk_net_if_t *ifp)
{
    int err, i;
    unsigned short rxd_num = NET_IF_DPDK_RX_RING_SIZE;
    unsigned short txd_num = NET_IF_DPDK_TX_RING_SIZE;
    struct rte_eth_txconf tx_conf;

    if (0 != (err = rte_eth_dev_configure(ifp->port_id,
        ifp->rxq_num, ifp->txq_num, &ifp->port_conf))) {
        lune_log(LUNE_WARN, "failed to configure %s: %d", ifp->name, err);
        return ERR_SET_ERR(LUNE_ERR_SYS_ERR);
    }

    if (0 != (err = rte_eth_dev_adjust_nb_rx_tx_desc(ifp->port_id, &rxd_num, &txd_num))) {
        lune_log(LUNE_WARN, "failed to adjust number of rx/tx on %s: %d", ifp->name, err);
        return ERR_SET_ERR(LUNE_ERR_SYS_ERR);
    }

    for (i = 0; i < ifp->txq_num; i++) {
        tx_conf = ifp->dev_info.default_txconf;
        tx_conf.offloads = ifp->port_conf.txmode.offloads;
        if (0 != (err = rte_eth_tx_queue_setup(ifp->port_id,
            i, txd_num, rte_eth_dev_socket_id(ifp->port_id), &tx_conf))) {
            lune_log(LUNE_WARN, "failed to setup tx queue on %s: %d", ifp->name, err);
            return ERR_SET_ERR(LUNE_ERR_SYS_ERR);
        }
    }

    ifp->rxd_num = rxd_num;
    ifp->txd_num = txd_num;

    return 0;
}

int net_if_dpdk_is_valid_chan_type(void *dpdk, lune_net_if_type_en type)
{
    net_if_dpdk_net_if_t *ifp = ((net_if_dpdk_t *)dpdk)->ifp;
    net_if_t *qifp = ((net_if_dpdk_t *)dpdk)->qifp;
    unsigned short chan_num;

    if (unlikely(NULL == NET_IF_GET_AGGR_NET_IF(qifp))) {
        /* not aggregated interface */
        return 0;
    }

    chan_num = AGGR_NET_IF_GET_TOTAL_CHAN_NUM(NET_IF_GET_AGGR_NET_IF(qifp));
    if ((NET_IF_DPDK_DEFAULT_TXQ_NUM == ifp->txq_num
        && LUNE_NET_IF_CHAN == type)
        || (chan_num == ifp->txq_num
        && LUNE_NET_IF_DPDK_CHAN == type)) {
        return 1;
    }

    return 0;
}

net_if_dpdk_net_if_t *net_if_dpdk_add_dpdk_net_if(const char *name,
    unsigned short rxq_num,
    unsigned short txq_num,
    lune_net_if_dpdk_rss_type_en rss_type)
{
    int found, i, ret;
    unsigned short port_id;
    net_if_dpdk_net_if_t *ifp;
    struct rte_eth_dev_info dev_info;

    if (s_net_if_dpdk_cnt >= NET_IF_DPDK_MAX_NET_IF_NUM) {
        ERR_SET_ERR(LUNE_ERR_EXCEED_LIMITS);
        goto ERR_1;
    }

    found = 0;
    RTE_ETH_FOREACH_DEV(port_id) {
        if (0 != (ret = rte_eth_dev_info_get(port_id, &dev_info))) {
            continue;
        }

#if RTE_VERSION >= RTE_VERSION_NUM(22, 11, 0, 0)
        if (!strcmp(name, rte_dev_name(dev_info.device))) {
#else
        if (!strcmp(name, dev_info.device->name)) {
#endif
            found = 1;
            break;
        }
    }

    if (!found) {
        ERR_SET_ERR(LUNE_ERR_NET_IF_NOT_FOUND);
        goto ERR_1;
    }

    if (NULL == (ifp = lune_malloc_mt(sizeof(net_if_dpdk_net_if_t)))) {
        goto ERR_1;
    }

    memcpy(&ifp->dev_info, &dev_info, sizeof(dev_info));

    if (1 == rxq_num) {
        lune_assert(LUNE_NET_IF_DPDK_RSS_TYPE_L3_NONE == rss_type);
    } else if (1 < rxq_num) {
        if (LUNE_NET_IF_DPDK_RSS_TYPE_L3_NONE == rss_type) {
            ERR_SET_ERR(LUNE_ERR_NOT_SUPPORTED);
            goto ERR_2;
        }
    }

    ifp->port_conf = s_dpdk_default_port_conf;

    if (ifp->dev_info.tx_offload_capa & DEV_TX_OFFLOAD_MBUF_FAST_FREE) {
        ifp->port_conf.txmode.offloads |= DEV_TX_OFFLOAD_MBUF_FAST_FREE;
    }

    /* tx checksum offload enabled by default */
    if (ifp->dev_info.tx_offload_capa & DEV_TX_OFFLOAD_IPV4_CKSUM) {
        ifp->port_conf.txmode.offloads |= DEV_TX_OFFLOAD_IPV4_CKSUM;
    }
    if (ifp->dev_info.tx_offload_capa & DEV_TX_OFFLOAD_TCP_CKSUM) {
        ifp->port_conf.txmode.offloads |= DEV_TX_OFFLOAD_TCP_CKSUM;
    }
    if (ifp->dev_info.tx_offload_capa & DEV_TX_OFFLOAD_UDP_CKSUM) {
        ifp->port_conf.txmode.offloads |= DEV_TX_OFFLOAD_UDP_CKSUM;
    }

    /* rx checksum offload enabled by default */
    if (ifp->dev_info.rx_offload_capa & DEV_RX_OFFLOAD_IPV4_CKSUM) {
        ifp->port_conf.rxmode.offloads |= DEV_RX_OFFLOAD_IPV4_CKSUM;
    }
    if (ifp->dev_info.rx_offload_capa & DEV_RX_OFFLOAD_TCP_CKSUM) {
        ifp->port_conf.rxmode.offloads |= DEV_RX_OFFLOAD_TCP_CKSUM;
    }
    if (ifp->dev_info.rx_offload_capa & DEV_RX_OFFLOAD_UDP_CKSUM) {
        ifp->port_conf.rxmode.offloads |= DEV_RX_OFFLOAD_UDP_CKSUM;
    }

    if (rss_type != LUNE_NET_IF_DPDK_RSS_TYPE_L3_NONE) {
        ifp->port_conf.rx_adv_conf.rss_conf.rss_key = NULL;
        ifp->port_conf.rx_adv_conf.rss_conf.rss_key_len = 0;
        ifp->port_conf.rx_adv_conf.rss_conf.rss_hf = ETH_RSS_IP;   /* default */
        ifp->port_conf.rxmode.mq_mode = ETH_MQ_RX_RSS;
    }

    ifp->rxq_num = rxq_num;
    ifp->txq_num = txq_num;
    ifp->port_id = port_id;

    if (0 != net_if_dpdk_configure(ifp)) {
        goto ERR_2;
    }

    strcpy(ifp->name, name);
    lune_assert(!rte_eth_dev_get_mtu(port_id, &ifp->mtu));

    ifp->flags = 0;
    NET_IF_DPDK_SET_DISTRIB(ifp);     /* default option for dpdk queue driver */

    ifp->queue_cnt = ifp->queue_enabled_cnt = 0;
    for (i = 0; i < NET_IF_DPDK_MAX_QUEUE_NUM; i++) {
        ifp->queue_array[i] = NULL;
    }
    pthread_spin_init(&ifp->lock, PTHREAD_PROCESS_PRIVATE);
    ifp->rss_type = rss_type;
    ifp->net_if_dpdk_cap = NULL;

    i = 0;
    while (i < NET_IF_DPDK_MAX_NET_IF_NUM) {
        if (NULL == s_net_if_dpdk_array[i]) {
            s_net_if_dpdk_array[i] = ifp;
            s_net_if_dpdk_cnt++;
            return ifp;
        }
        i++;
    }

    lune_assert(!pthread_spin_destroy(&ifp->lock));

ERR_2:
    lune_free_mt(ifp);

ERR_1:
    return NULL;
}

void net_if_dpdk_del_dpdk_net_if(net_if_dpdk_net_if_t *ifp)
{
    int i;

    for (i = 0; i < NET_IF_DPDK_MAX_NET_IF_NUM; i++) {
        if (ifp == s_net_if_dpdk_array[i]) {
            s_net_if_dpdk_array[i] = NULL;
            s_net_if_dpdk_cnt--;
        }
    }

    lune_assert(!pthread_spin_destroy(&ifp->lock));
    lune_free_mt(ifp);
}

static int net_if_dpdk_add_net_if(net_if_t *ifp,
    const char *name, const void *conf_val, unsigned int conf_len, void **pdata)
{
    net_if_dpdk_t *dpdk;
    int err, i;
    char mbuf_pool_name[LUNE_MAX_NAME_BUF_LEN];
    unsigned short rxq_num, txq_num;
    struct rte_eth_rxconf rx_conf;
    net_if_dpdk_net_if_t *dpdk_ifp;

    if (NULL == conf_val) {
        txq_num = NET_IF_DPDK_DEFAULT_TXQ_NUM;
    } else if (sizeof(lune_net_if_dpdk_conf_t) == conf_len) {
        txq_num = ((const lune_net_if_dpdk_conf_t *)conf_val)->txq_num;
    } else {
        err = ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        goto ERR_1;
    }

    rxq_num = 1;

    if (NULL == (dpdk = lune_malloc(sizeof(net_if_dpdk_t)))) {
        err = ERR_GET_LAST_ERR();
        goto ERR_1;
    }

    pthread_spin_lock(&g_net_if_dpdk_lock);
    if (NULL != (dpdk_ifp = net_if_dpdk_get_dpdk_net_if_by_name(name))) {
        pthread_spin_unlock(&g_net_if_dpdk_lock);
        err = ERR_SET_ERR(LUNE_ERR_ALREADY_EXIST);
        goto ERR_2;
    }

    if (NULL == (dpdk_ifp = net_if_dpdk_add_dpdk_net_if(name,
        rxq_num, txq_num, LUNE_NET_IF_DPDK_RSS_TYPE_L3_NONE))) {
        pthread_spin_unlock(&g_net_if_dpdk_lock);
        err = ERR_GET_LAST_ERR();
        goto ERR_2;
    }
    pthread_spin_unlock(&g_net_if_dpdk_lock);

    sprintf(mbuf_pool_name, "dpdk mbuf pool %d", CORE_GET_ID());
    if (NULL == g_net_if_dpdk_send_mbuf_pool) {
        if (NULL == (g_net_if_dpdk_send_mbuf_pool = rte_pktmbuf_pool_create(mbuf_pool_name,
            NET_IF_DPDK_MBUF_NUM,
            32,
            0,
            RTE_MBUF_DEFAULT_BUF_SIZE,
            rte_socket_id()))) {
            lune_log(LUNE_WARN, "failed to create mbuf pool on %s: %s",
                name, rte_strerror(rte_errno));
            err = ERR_SET_ERR(LUNE_ERR_NET_IF_INTERNAL);
            goto ERR_3;
        }
    }

    rx_conf = dpdk_ifp->dev_info.default_rxconf;
    rx_conf.offloads = dpdk_ifp->port_conf.rxmode.offloads;
    if (0 != (err = rte_eth_rx_queue_setup(dpdk_ifp->port_id, 0, dpdk_ifp->rxd_num,
        rte_eth_dev_socket_id(dpdk_ifp->port_id), &rx_conf, g_net_if_dpdk_send_mbuf_pool))) {
        lune_log(LUNE_WARN, "failed to setup rx queue on %s: %d", name, err);
        err = ERR_SET_ERR(LUNE_ERR_SYS_ERR);
        goto ERR_3;
    }

    dpdk->flags = 0;

    for (i = 0; i < NET_IF_DPDK_MAX_RX_PKT_BURST; i++) {
        dpdk->rx_pkts_burst[i] = NULL;
    }

    for (i = 0; i < NET_IF_DPDK_MAX_TX_PKT_BURST; i++) {
        dpdk->tx_pkts_burst[i] = NULL;
    }

    rte_eth_promiscuous_enable(dpdk_ifp->port_id);

    dpdk->ifp = dpdk_ifp;
    dpdk->qifp = ifp;
    *pdata = dpdk;

    return 0;

ERR_3:
    pthread_spin_lock(&g_net_if_dpdk_lock);
    net_if_dpdk_del_dpdk_net_if(dpdk_ifp);
    pthread_spin_unlock(&g_net_if_dpdk_lock);

ERR_2:
    lune_free(dpdk);

ERR_1:
    return err;
}

static int net_if_dpdk_del_net_if(net_if_dpdk_t *dpdk)
{
    pthread_spin_lock(&g_net_if_dpdk_lock);
    net_if_dpdk_del_dpdk_net_if(dpdk->ifp);
    pthread_spin_unlock(&g_net_if_dpdk_lock);
    lune_free(dpdk);
    return 0;
}

static int net_if_dpdk_is_up(net_if_dpdk_t *dpdk)
{
    return NET_IF_DPDK_IS_UP(dpdk);
}

static void net_if_dpdk_send_tx_burst(net_if_dpdk_t *dpdk)
{
    int i, j;
    unsigned int tx_num;

    if (likely(dpdk->tx_offset > 0)) {
        tx_num = rte_eth_tx_burst(dpdk->ifp->port_id, 0, dpdk->tx_pkts_burst, dpdk->tx_offset);
        if (unlikely(tx_num != dpdk->tx_offset)) {
            for (i = 0, j = tx_num; j < dpdk->tx_offset; i++, j++) {
                dpdk->tx_pkts_burst[i] = dpdk->tx_pkts_burst[j];
            }
            dpdk->tx_offset = dpdk->tx_offset - tx_num;
        } else {
            dpdk->tx_offset = 0;
        }
    }
}

static int net_if_dpdk_set_up(net_if_dpdk_t *dpdk)
{
    int err;
    net_if_dpdk_net_if_t *ifp = dpdk->ifp;

    dpdk->tx_task_id = LUNE_INVALID_ID;
    dpdk->pkt_in_ipv4_csum_err = dpdk->pkt_in_l4_csum_err = 0;
    dpdk->rx_num = dpdk->rx_offset = dpdk->tx_offset = 0;

    if (!NET_IF_IS_AGGR(dpdk->qifp)
        || AGGR_NET_IF_IS_AGGR_SEND(NET_IF_GET_AGGR_NET_IF(dpdk->qifp))) {
        if (LUNE_INVALID_ID == (dpdk->tx_task_id = sched_add_task(ifp->name,
            (lune_task_func_t)net_if_dpdk_send_tx_burst, (void *)dpdk, SCHED_PRIO_SEND))) {
            lune_log(LUNE_CRIT, "failed to add send task on %s: %s", ifp->name, ERR_GET_LAST_ERR_STR());
            goto ERR_1;
        }
    } else {
        /* aggregated interface with channels of LUNE_NET_IF_DPDK_CHAN type */
    }

    if (0 != (err = rte_eth_dev_start(ifp->port_id))) {
        lune_log(LUNE_CRIT, "failed to start %s: %d", ifp->name, err);
        ERR_SET_ERR(LUNE_ERR_NET_IF_INTERNAL);
        goto ERR_2;
    }

    NET_IF_DPDK_SET_UP(dpdk);
    return 0;

ERR_2:
    if (LUNE_INVALID_ID != dpdk->tx_task_id) {
        lune_assert(!sched_del_task(dpdk->tx_task_id));
        dpdk->tx_task_id = LUNE_INVALID_ID;
    }

ERR_1:
    return ERR_GET_LAST_ERR();
}

static int net_if_dpdk_set_down(net_if_dpdk_t *dpdk)
{
    net_if_dpdk_net_if_t *ifp = dpdk->ifp;

    rte_eth_dev_stop(ifp->port_id);

    if (NET_IF_DPDK_IS_CAP_ENABLED(ifp)) {
        /*
            stop packet capture once interface disabled
        */
        net_if_dpdk_cap_stop(ifp->net_if_dpdk_cap);
        ifp->net_if_dpdk_cap = NULL;
    }

    if (LUNE_INVALID_ID != dpdk->tx_task_id) {
        lune_assert(!sched_del_task(dpdk->tx_task_id));
        dpdk->tx_task_id = LUNE_INVALID_ID;
    }

    dpdk->tx_task_id = LUNE_INVALID_ID;
    dpdk->pkt_in_ipv4_csum_err = dpdk->pkt_in_l4_csum_err = 0;
    dpdk->rx_num = dpdk->rx_offset = dpdk->tx_offset = 0;

    NET_IF_DPDK_SET_DOWN(dpdk);
    return 0;
}

static int net_if_dpdk_send(net_if_dpdk_t *dpdk, const unsigned char *buf, unsigned int len)
{
    int i, j, tx_num, zero_copy;
    struct rte_mbuf *mbuf;
    unsigned char *p;
    pbuf_t *pbuf;
    net_if_dpdk_net_if_t *ifp = dpdk->ifp;

    if (NULL != (pbuf = NET_IF_GET_CURR_TX_PBUF())
        && NULL != pbuf->mbuf) {
        mbuf = pbuf->mbuf;
        pbuf->mbuf = NULL;
        zero_copy = 1;
#ifdef LUNE_DEBUG
        lune_assert(mbuf->data_len == len);
        lune_assert(rte_pktmbuf_mtod(mbuf, unsigned char *) == buf);
#endif
    } else {
        if (NULL == (mbuf = rte_pktmbuf_alloc(g_net_if_dpdk_send_mbuf_pool))) {
            lune_log(LUNE_WARN, "failed to allocate tx pktmbuf for %s", ifp->name);
            return ERR_SET_ERR(LUNE_ERR_NET_IF_INTERNAL);
        }

        mbuf->data_len = len;

        zero_copy = 0;
    }

    mbuf->pkt_len = len;
    mbuf->tx_offload = 0;
    if (NULL != pbuf) {
        mbuf->l2_len = pbuf->l2_len;
        mbuf->l3_len = pbuf->l3_len;
        mbuf->l4_len = pbuf->l4_len;
        if (PBUF_IS_L3_IPV4(pbuf)) {
            mbuf->ol_flags |= PKT_TX_IPV4;
            if (ifp->port_conf.txmode.offloads & DEV_TX_OFFLOAD_IPV4_CKSUM) {
                mbuf->ol_flags |= PKT_TX_IP_CKSUM;
            }
        }

        switch (PBUF_GET_L4_TYPE(pbuf)) {
        case PBUF_L4_TYPE_TCP:
            if (ifp->port_conf.txmode.offloads & DEV_TX_OFFLOAD_TCP_CKSUM) {
                mbuf->ol_flags |= PKT_TX_TCP_CKSUM;
            }
            break;
        case PBUF_L4_TYPE_UDP:
            if (ifp->port_conf.txmode.offloads & DEV_TX_OFFLOAD_UDP_CKSUM) {
                mbuf->ol_flags |= PKT_TX_UDP_CKSUM;
            }
            break;
        default:
            break;
        }
    }

    p = rte_pktmbuf_mtod(mbuf, unsigned char *);

    if (!zero_copy) {
        memcpy(p, buf, len);
    }

    dpdk->tx_pkts_burst[dpdk->tx_offset++] = mbuf;

    NET_IF_DPDK_CAP_PKT_OUT(ifp, p, len);

    if (dpdk->tx_offset >= NET_IF_DPDK_MAX_TX_PKT_BURST) {
        tx_num = rte_eth_tx_burst(ifp->port_id, 0, dpdk->tx_pkts_burst, NET_IF_DPDK_MAX_TX_PKT_BURST);
        if (unlikely(tx_num != NET_IF_DPDK_MAX_TX_PKT_BURST)) {
            for (i = 0, j = tx_num; j < NET_IF_DPDK_MAX_TX_PKT_BURST; i++, j++) {
                dpdk->tx_pkts_burst[i] = dpdk->tx_pkts_burst[j];
            }
            dpdk->tx_offset = NET_IF_DPDK_MAX_TX_PKT_BURST - tx_num;
        } else {
            dpdk->tx_offset = 0;
        }
    }

    return 0;
}

static int net_if_dpdk_send_pkts(net_if_dpdk_t *dpdk, const net_if_send_pkt_t *pkts, unsigned int pkt_num)
{
    int err;
    unsigned int i, j, n, tx_num, send_num, sent_num;
    struct rte_mbuf *mbufs[NET_IF_DPDK_MAX_TX_PKT_BURST];
    unsigned char *p;
    net_if_dpdk_net_if_t *ifp = dpdk->ifp;

#ifdef LUNE_DEBUG
    lune_assert(NULL == NET_IF_GET_CURR_TX_PBUF());
#endif

    i = 0;
    sent_num = 0;
    send_num = pkt_num;

SEND_PKTS:
    if (send_num > (unsigned int)(NET_IF_DPDK_MAX_TX_PKT_BURST - dpdk->tx_offset)) {
        n = (unsigned int)(NET_IF_DPDK_MAX_TX_PKT_BURST - dpdk->tx_offset);
    } else {
        n = send_num;
    }

    if (0 != (err = rte_pktmbuf_alloc_bulk(g_net_if_dpdk_send_mbuf_pool, mbufs, n))) {
        if (0 == sent_num) {
            /* no packet sent */
            lune_log(LUNE_WARN, "failed to allocate %d tx pktmbufs for %s: error %d",
                n, ifp->name, err);
            return ERR_SET_ERR(LUNE_ERR_NET_IF_INTERNAL);
        }

        return sent_num;
    }

    for (j = 0; j < n; i++, j++) {
        mbufs[j]->data_len = mbufs[j]->pkt_len = pkts[i].len;
        mbufs[j]->tx_offload = 0;

        p = rte_pktmbuf_mtod(mbufs[j], unsigned char *);
        memcpy(p, pkts[i].buf, pkts[i].len);

        dpdk->tx_pkts_burst[dpdk->tx_offset++] = mbufs[j];

        NET_IF_DPDK_CAP_PKT_OUT(ifp, pkts[i].buf, pkts[i].len);
    }

    sent_num += n;

    tx_num = rte_eth_tx_burst(ifp->port_id, 0, dpdk->tx_pkts_burst, dpdk->tx_offset);
    if (unlikely(dpdk->tx_offset > tx_num)) {
        for (i = 0, j = tx_num; j < dpdk->tx_offset; i++, j++) {
            dpdk->tx_pkts_burst[i] = dpdk->tx_pkts_burst[j];
        }
        dpdk->tx_offset = dpdk->tx_offset - tx_num;

        return sent_num;
    }

    dpdk->tx_offset = 0;
    send_num -= tx_num;
    if (send_num > 0) {
        goto SEND_PKTS;
    }

    return sent_num;
}

static int net_if_dpdk_recv(net_if_dpdk_t *dpdk, unsigned char **pbuf, unsigned int *plen)
{
    struct rte_mbuf *mbuf;
    int err;
    unsigned int len;

NEXT:
    if (dpdk->rx_num == dpdk->rx_offset) {
        dpdk->rx_offset = 0;
        dpdk->rx_num = rte_eth_rx_burst(dpdk->ifp->port_id, 0,
            dpdk->rx_pkts_burst, NET_IF_DPDK_MAX_RX_PKT_BURST);
        if (0 == dpdk->rx_num) {
            /* ERR_SET_ERR() unneeded */
            return -LUNE_ERR_NET_IF_NO_PKT;
        }
    }

    mbuf = dpdk->rx_pkts_burst[dpdk->rx_offset];
    len = rte_pktmbuf_data_len(mbuf);

    err = 0;
    if (unlikely((mbuf->ol_flags & PKT_RX_IP_CKSUM_MASK) == PKT_RX_IP_CKSUM_BAD)) {
        dpdk->pkt_in_ipv4_csum_err++;
        err = 1;
    }
    if (unlikely((mbuf->ol_flags & PKT_RX_L4_CKSUM_MASK) == PKT_RX_L4_CKSUM_BAD)) {
        dpdk->pkt_in_l4_csum_err++;
        err = 1;
    }

    net_if_dpdk_mbuf_init_and_hold(mbuf);

    if (unlikely(err)) {
        /* skip packet with error */
        net_if_dpdk_mbuf_put(mbuf);
        dpdk->rx_offset++;
        goto NEXT;
    }

    *pbuf = rte_pktmbuf_mtod(mbuf, unsigned char *);
    *plen = len;
    return 0;
}

static int net_if_dpdk_recv_pkts(net_if_dpdk_t *dpdk)
{
    int i, err, last_err = 0;
    unsigned int len, attempts;
    struct rte_mbuf *mbuf;
    unsigned short rx_num;
    net_if_dpdk_net_if_t *ifp = dpdk->ifp;

    attempts = 0;
    while (attempts++ < NET_IF_DPDK_MAX_RECV_PKTS_ATTEMPTS) {
        rx_num = rte_eth_rx_burst(ifp->port_id,
            0, dpdk->rx_pkts_burst, NET_IF_DPDK_MAX_RX_PKT_BURST);
        if (0 == rx_num) {
            continue;
        }

        dpdk->rx_offset = 0;
        for (i = 0; i < rx_num; i++) {
            mbuf = dpdk->rx_pkts_burst[i];
            len = rte_pktmbuf_data_len(mbuf);

            err = 0;
            if (unlikely((mbuf->ol_flags & PKT_RX_IP_CKSUM_MASK) == PKT_RX_IP_CKSUM_BAD)) {
                dpdk->pkt_in_ipv4_csum_err++;
                err = 1;
            }
            if (unlikely((mbuf->ol_flags & PKT_RX_L4_CKSUM_MASK) == PKT_RX_L4_CKSUM_BAD)) {
                dpdk->pkt_in_l4_csum_err++;
                err = 1;
            }

            net_if_dpdk_mbuf_init_and_hold(mbuf);

            NET_IF_DPDK_CAP_MBUF_IN(ifp, mbuf);

            if (unlikely(err)) {
                /* skip packet with error */
                net_if_dpdk_mbuf_put(mbuf);
                dpdk->rx_offset++;
                continue;
            }

            err = net_if_process_single_net_if_recv_func(dpdk->qifp,
                rte_pktmbuf_mtod(mbuf, unsigned char *), len, 1);
            if (unlikely(0 != err)) {
                last_err = err;
            }

            if (i == dpdk->rx_offset) {
                /* recv_fwd_pkt once */
                net_if_dpdk_mbuf_put(mbuf);
                dpdk->rx_offset++;
            } else {
                /*
                    recv_done once, or
                    multiple recv_fwd_pkt and recv_done once
                */
            }
        }
    }

    return last_err;
}

static void net_if_dpdk_recv_done(net_if_dpdk_t *dpdk)
{
    net_if_dpdk_mbuf_put(dpdk->rx_pkts_burst[dpdk->rx_offset++]);
}

static void net_if_dpdk_recv_fwd_pkt(net_if_dpdk_t *dpdk, void **pdata)
{
    *pdata = dpdk->rx_pkts_burst[dpdk->rx_offset];
    net_if_dpdk_mbuf_hold(*pdata);
}

static void net_if_dpdk_recv_free_pkt(net_if_dpdk_t *dpdk __attribute__((unused)),
    unsigned char *buf __attribute__((unused)), void *data)
{
    net_if_dpdk_mbuf_put(data);
}

static int net_if_dpdk_get_opt(net_if_dpdk_t *dpdk,
    net_if_opt_en opt, unsigned char *opt_val, unsigned int opt_len)
{
    lune_assert(NULL != opt_val);
    net_if_dpdk_net_if_t *ifp = dpdk->ifp;

    switch (opt) {
    case NET_IF_OPT_GET_HW_CSUM:
    {
        unsigned short csum_offloads;

        if (opt_len != sizeof(unsigned short)) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        csum_offloads = 0;
        if (ifp->port_conf.rxmode.offloads & DEV_RX_OFFLOAD_IPV4_CKSUM) {
            NET_IF_OPT_SET_HW_RX_CSUM_IPV4(csum_offloads);
        }
        if (ifp->port_conf.rxmode.offloads & DEV_RX_OFFLOAD_TCP_CKSUM) {
            NET_IF_OPT_SET_HW_RX_CSUM_TCP(csum_offloads);
        }
        if (ifp->port_conf.rxmode.offloads & DEV_RX_OFFLOAD_UDP_CKSUM) {
            NET_IF_OPT_SET_HW_RX_CSUM_UDP(csum_offloads);
        }
        if (ifp->port_conf.txmode.offloads & DEV_TX_OFFLOAD_IPV4_CKSUM) {
            NET_IF_OPT_SET_HW_TX_CSUM_IPV4(csum_offloads);
        }
        if (ifp->port_conf.txmode.offloads & DEV_TX_OFFLOAD_TCP_CKSUM) {
            NET_IF_OPT_SET_HW_TX_CSUM_TCP(csum_offloads);
        }
        if (ifp->port_conf.txmode.offloads & DEV_TX_OFFLOAD_UDP_CKSUM) {
            NET_IF_OPT_SET_HW_TX_CSUM_UDP(csum_offloads);
        }

        *(unsigned short *)opt_val = csum_offloads;
        break;
    }
    case NET_IF_OPT_GET_MAX_DATA_RATE:
        /*
            always asked while new interface being added, no need to report error
        */
        return -LUNE_ERR_NOT_SUPPORTED;
    case NET_IF_OPT_GET_MTU:
        if (opt_len != sizeof(unsigned short)) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        *(unsigned short *)opt_val = ifp->mtu;
        break;
    case NET_IF_OPT_GET_STATS:
    {
        lune_net_if_stats_t *pstats;
        struct rte_eth_stats stats;

        if (opt_len != sizeof(lune_net_if_stats_t)) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        pstats = (lune_net_if_stats_t *)opt_val;

        if (0 != (rte_eth_stats_get(ifp->port_id, &stats))) {
            lune_log(LUNE_INFO, "failed to get statistics of %s", ifp->name);
            return ERR_SET_ERR(LUNE_ERR_NET_IF_INTERNAL);
        }

        pstats->pkt_in = stats.ipackets;
        pstats->pkt_out = stats.opackets;
        pstats->pkt_in_dropped = stats.ierrors;
        pstats->pkt_out_dropped = stats.oerrors;
        pstats->pkt_in_ipv4_csum_err = dpdk->pkt_in_ipv4_csum_err;
        pstats->pkt_in_l4_csum_err = dpdk->pkt_in_l4_csum_err;
        pstats->byte_in = stats.ibytes;
        pstats->byte_out = stats.obytes;

        break;
    }
    case NET_IF_OPT_GET_PORT_ID:
        if (opt_len != sizeof(unsigned short)) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        *(unsigned short *)opt_val = ifp->port_id;
        break;
    case NET_IF_OPT_IS_RECV_REFCNT_AVAIL:
        if (opt_len != sizeof(unsigned int)) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        *(unsigned int *)opt_val = 1;
        break;
    default:
        return ERR_SET_ERR(LUNE_ERR_NOT_SUPPORTED);
    }

    return 0;
}

static int net_if_dpdk_set_opt(net_if_dpdk_t *dpdk,
    net_if_opt_en opt,
    const unsigned char *opt_val,
    unsigned int opt_len __attribute__((unused)))
{
    int err;
    net_if_dpdk_net_if_t *ifp = dpdk->ifp;

    switch (opt) {
    case NET_IF_OPT_SET_MTU:
        /* TODO: set mtu to dpdk driver */
        ifp->mtu = *(const unsigned short *)opt_val;
        break;
    case NET_IF_OPT_PCAP_START:
        if (NET_IF_DPDK_IS_CAP_ENABLED(ifp)) {
            return ERR_SET_ERR(LUNE_ERR_ALREADY_STARTED);
        }

        if (NULL == (ifp->net_if_dpdk_cap = net_if_dpdk_cap_start(ifp->name,
            ((const lune_net_if_pcap_t *)opt_val)->file_name))) {
            return ERR_GET_LAST_ERR();
        }

        return 0;
    case NET_IF_OPT_PCAP_STOP:
        if (!NET_IF_DPDK_IS_CAP_ENABLED(ifp)) {
            lune_assert(NULL == ifp->net_if_dpdk_cap);
            return ERR_SET_ERR(LUNE_ERR_NOT_STARTED);
        }

        net_if_dpdk_cap_stop(ifp->net_if_dpdk_cap);
        ifp->net_if_dpdk_cap = NULL;
        return 0;
    case NET_IF_OPT_DISABLE_HW_CSUM:
        ifp->port_conf.rxmode.offloads &=
            ~(DEV_RX_OFFLOAD_IPV4_CKSUM | DEV_RX_OFFLOAD_TCP_CKSUM | DEV_RX_OFFLOAD_UDP_CKSUM);
        ifp->port_conf.txmode.offloads &=
            ~(DEV_TX_OFFLOAD_IPV4_CKSUM | DEV_TX_OFFLOAD_TCP_CKSUM | DEV_TX_OFFLOAD_UDP_CKSUM);

        if (0 != (err = rte_eth_dev_configure(ifp->port_id,
            ifp->rxq_num, ifp->txq_num, &ifp->port_conf))) {
            lune_log(LUNE_WARN, "failed to configure %s: %d", ifp->name, err);
            return ERR_SET_ERR(LUNE_ERR_SYS_ERR);
        }

        break;
    default:
        return ERR_SET_ERR(LUNE_ERR_NOT_SUPPORTED);
    }

    return 0;
}

net_if_dpdk_net_if_t *net_if_dpdk_get_dpdk_net_if_by_name(const char *name)
{
    int i;

    lune_assert(NULL != name);

    for (i = 0; i < NET_IF_DPDK_MAX_NET_IF_NUM; i++) {
        if (NULL == s_net_if_dpdk_array[i]) {
            break;
        }

        if (!strcmp(name, s_net_if_dpdk_array[i]->name)) {
            return s_net_if_dpdk_array[i];
        }
    }

    return NULL;
}

net_if_dpdk_net_if_t *net_if_dpdk_get_dpdk_net_if(void *dpdk)
{
    return ((net_if_dpdk_t *)dpdk)->ifp;
}

int net_if_dpdk_init(void)
{
    int ret, i;
    unsigned short port_num;
    int argc = 1;
    char argv1[256];
    char *argv[] = { argv1 };

    strcpy(argv1, "net_if_dpdk");
    if (0 > (ret = rte_eal_init(argc, argv))) {
        ERR_SET_ERR(LUNE_ERR_NET_IF_INTERNAL);
        goto ERR_1;
    }

    port_num = rte_eth_dev_count_avail();
    if (0 == port_num) {
        lune_log(LUNE_INFO, "no dpdk port found while initializing dpdk");
        /* keep going */
    }

    if (0 != pthread_spin_init(&g_net_if_dpdk_lock, PTHREAD_PROCESS_PRIVATE)) {
        ERR_SET_ERR(LUNE_ERR_SYS_ERR);
        lune_log(LUNE_CRIT, "failed to initialize dpdk interface lock: %s", strerror(errno));
        goto ERR_2;
    }

    s_net_if_dpdk_cnt = 0;
    for (i = 0; i < NET_IF_DPDK_MAX_NET_IF_NUM; i++) {
        s_net_if_dpdk_array[i] = NULL;
    }

    return 0;

ERR_2:
    lune_assert(!rte_eal_cleanup());

ERR_1:
    return ERR_GET_LAST_ERR();
}

void net_if_dpdk_fini(void)
{
    if (s_net_if_dpdk_cnt != 0) {
        int i;
        for (i = 0; i < NET_IF_DPDK_MAX_NET_IF_NUM; i++) {
            if (NULL != s_net_if_dpdk_array[i]) {
                lune_log(LUNE_INFO, "dpdk port %s not deleted while cleaning up dpdk",
                    s_net_if_dpdk_array[i]->name);
                s_net_if_dpdk_array[i] = NULL;
            }
        }
    }
    lune_assert(!pthread_spin_destroy(&g_net_if_dpdk_lock));
    lune_assert(!rte_eal_cleanup());
}

int net_if_dpdk_local_init(void)
{
    g_net_if_dpdk_send_mbuf_pool = NULL;
    return 0;
}

void net_if_dpdk_local_fini(void)
{
    if (NULL != g_net_if_dpdk_send_mbuf_pool) {
        rte_mempool_free(g_net_if_dpdk_send_mbuf_pool);
    }
}

net_if_drv_t g_net_if_drv_dpdk = {
    .type = LUNE_NET_IF_DPDK,
    .name = "dpdk",
    .add_net_if = (net_if_add_net_if_func_t)net_if_dpdk_add_net_if,
    .del_net_if = (net_if_del_net_if_func_t)net_if_dpdk_del_net_if,
    .is_up = (net_if_is_up_func_t)net_if_dpdk_is_up,
    .set_up = (net_if_set_up_func_t)net_if_dpdk_set_up,
    .set_down = (net_if_set_down_func_t)net_if_dpdk_set_down,
    .send = (net_if_send_func_t)net_if_dpdk_send,
    .send_pkts = (net_if_send_pkts_func_t)net_if_dpdk_send_pkts,
    .recv = (net_if_recv_func_t)net_if_dpdk_recv,
    .recv_pkts = (net_if_recv_pkts_func_t)net_if_dpdk_recv_pkts,
    .recv_done = (net_if_recv_done_func_t)net_if_dpdk_recv_done,
    .recv_fwd_pkt = (net_if_recv_fwd_pkt_func_t)net_if_dpdk_recv_fwd_pkt,
    .recv_free_pkt = (net_if_recv_free_pkt_func_t)net_if_dpdk_recv_free_pkt,
    .get_opt = (net_if_get_opt_func_t)net_if_dpdk_get_opt,
    .set_opt = (net_if_set_opt_func_t)net_if_dpdk_set_opt,
};
