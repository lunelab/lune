/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2024 Lune Reseau, Inc.
 */

#include <rte_ethdev.h>
#include <rte_mbuf.h>

#include "lune/log.h"
#include "lune/mem.h"
#include "lune/net_if.h"
#include "lune/os/linux.h"
#include "lune/time.h"
#include "lune/timer.h"

#include "drv/aggr.h"
#include "drv/dpdk/net_if_dpdk_chan.h"
#include "drv/net_if.h"
#include "kernel/sched.h"
#include "net/socket.h"
#include "rt/core.h"
#include "utils/cap.h"

/*
    according to rte_pktmbuf_pool_create:

    The optimum size (in terms of memory usage) for a mempool is
    when n is a power of two minus one: n = (2^q - 1).
*/
#define NET_IF_DPDK_CHAN_MBUF_NUM                  (1024 * 64 - 1)

typedef struct _net_if_dpdk_chan {
    char name[LUNE_MAX_SHORT_NAME_BUF_LEN];
    void *acp;
    net_if_t *ifp;
    lune_net_if_stats_t stats;
    unsigned short mtu;
    unsigned short csum_offloads;
    unsigned short port_id;
    unsigned short txq_id;
    unsigned int tx_offset;
    unsigned int tx_task_id;
#define NET_IF_DPDK_CHAN_FLAG_UP                   0x00000001
#define NET_IF_DPDK_CHAN_IS_UP(chan)               \
    (((net_if_dpdk_chan_t *)(chan))->flags & NET_IF_DPDK_CHAN_FLAG_UP)
#define NET_IF_DPDK_CHAN_SET_UP(chan)              \
    do { ((net_if_dpdk_chan_t *)(chan))->flags =   \
        (((net_if_dpdk_chan_t *)(chan))->flags | (NET_IF_DPDK_CHAN_FLAG_UP)); } while (0)
#define NET_IF_DPDK_CHAN_SET_DOWN(chan)            \
    do { ((net_if_dpdk_chan_t *)(chan))->flags =   \
        (((net_if_dpdk_chan_t *)(chan))->flags & (~NET_IF_DPDK_CHAN_FLAG_UP)); } while (0)
    unsigned long long flags;
#define NET_IF_DPDK_CHAN_MAX_TX_PKT_BURST          (32)
    struct rte_mbuf *tx_pkts_burst[NET_IF_DPDK_CHAN_MAX_TX_PKT_BURST];
    net_if_t *ai_ifp;
    net_if_dpdk_net_if_t *dpdk_ifp;
} net_if_dpdk_chan_t;

static int net_if_dpdk_chan_init_chan(net_if_dpdk_chan_t *chan, const char *name, net_if_t *ifp)
{
    int err, i;
    char mbuf_pool_name[LUNE_MAX_NAME_BUF_LEN];
    net_if_t *ai_ifp;
    unsigned short chan_id;

    if (NULL == (chan->acp = aggr_add_chan(name, ifp))) {
        err = ERR_GET_LAST_ERR();
        goto ERR_1;
    }

    strcpy(chan->name, name);
    chan->ifp = ifp;
    memset(&chan->stats, 0x00, sizeof(lune_net_if_stats_t));
    /* ifp->mtu has been updated within aggr_add_chan() */
    chan->mtu = ifp->mtu;

    lune_assert(NULL != (ai_ifp = aggr_chan_get_aggr_ifp(chan->acp)));
    if (ai_ifp->type != LUNE_NET_IF_DPDK) {
        err = ERR_SET_ERR(LUNE_ERR_NOT_SUPPORTED);
        goto ERR_2;
    }

    if (0 != (err = ai_ifp->drv->get_opt(ai_ifp->net_if_data,
        NET_IF_OPT_GET_HW_CSUM, (unsigned char *)&chan->csum_offloads, sizeof(chan->csum_offloads)))) {
        goto ERR_2;
    }

    if (0 != (err = ai_ifp->drv->get_opt(ai_ifp->net_if_data,
        NET_IF_OPT_GET_PORT_ID, (unsigned char *)&chan->port_id, sizeof(chan->port_id)))) {
        goto ERR_2;
    }

    chan_id = (unsigned short)aggr_chan_get_id(chan->acp);
    chan->txq_id = chan_id;
    chan->tx_offset = 0;
    chan->tx_task_id = LUNE_INVALID_ID;
    chan->flags = 0;

    for (i = 0; i < NET_IF_DPDK_CHAN_MAX_TX_PKT_BURST; i++) {
        chan->tx_pkts_burst[i] = NULL;
    }

    sprintf(mbuf_pool_name, "dpdk mbuf pool %d", CORE_GET_ID());
    if (NULL == g_net_if_dpdk_send_mbuf_pool) {
        if (NULL == (g_net_if_dpdk_send_mbuf_pool = rte_pktmbuf_pool_create(mbuf_pool_name,
            NET_IF_DPDK_CHAN_MBUF_NUM,
            32,
            0,
            RTE_MBUF_DEFAULT_BUF_SIZE,
            rte_socket_id()))) {
            lune_log(LUNE_WARN, "failed to create mbuf pool for dpdk channel interface %s: %s",
                name, rte_strerror(rte_errno));
            err = ERR_SET_ERR(LUNE_ERR_NO_MEM);
            goto ERR_2;
        }
    }

    chan->ai_ifp = ai_ifp;
    lune_assert(NULL != (chan->dpdk_ifp =
        net_if_dpdk_get_dpdk_net_if(ai_ifp->net_if_data)));
    net_if_hold(ai_ifp);

    return 0;

ERR_2:
    lune_assert(!aggr_del_chan(chan->acp));

ERR_1:
    return err;
}

static int net_if_dpdk_chan_add_net_if(net_if_t *ifp,
    const char *name, const void *conf_val, unsigned int conf_len, void **pdata)
{
    net_if_dpdk_chan_t *chan;
    int err;

    if (conf_val != NULL || conf_len != 0) {
        err = ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        goto ERR_1;
    }

    if (NULL == (chan = lune_malloc(sizeof(net_if_dpdk_chan_t)))) {
        err = ERR_GET_LAST_ERR();
        goto ERR_1;
    }

    if (0 != (err = net_if_dpdk_chan_init_chan(chan, name, ifp))) {
        goto ERR_2;
    }

    *pdata = chan;

    return 0;

ERR_2:
    lune_free(chan);

ERR_1:
    return err;
}

static int net_if_dpdk_chan_del_net_if(net_if_dpdk_chan_t *chan)
{
    int err;

    lune_assert(NULL != chan->acp);
    lune_assert(NULL != chan->ai_ifp);

    net_if_put(chan->ai_ifp);

    if (0 != (err = aggr_del_chan(chan->acp))) {
        return err;
    }

    lune_free(chan);
    return 0;
}

static int net_if_dpdk_chan_is_up(net_if_dpdk_chan_t *chan)
{
    return NET_IF_DPDK_CHAN_IS_UP(chan);
}

static void net_if_dpdk_chan_send_tx_burst(net_if_dpdk_chan_t *chan)
{
    unsigned int i, j;
    unsigned int tx_num;

    if (likely(chan->tx_offset > 0)) {
        tx_num = rte_eth_tx_burst(chan->port_id,
            chan->txq_id, chan->tx_pkts_burst, chan->tx_offset);
        if (unlikely(tx_num != chan->tx_offset)) {
            for (i = 0, j = tx_num; j < chan->tx_offset; i++, j++) {
                chan->tx_pkts_burst[i] = chan->tx_pkts_burst[j];
            }
            chan->tx_offset = chan->tx_offset - tx_num;
        } else {
            chan->tx_offset = 0;
        }
    }
}

static int net_if_dpdk_chan_set_up(net_if_dpdk_chan_t *chan)
{
    lune_assert(NULL != chan->ai_ifp);

    if (!NET_IF_IS_ACTIVE(chan->ai_ifp)) {
        /* aggregated interface should be enabled first */
        return ERR_SET_ERR(LUNE_ERR_NET_IF_AGGR_NOT_ENABLED);
    }

    if (LUNE_INVALID_ID == (chan->tx_task_id = sched_add_task(chan->name,
        (lune_task_func_t)net_if_dpdk_chan_send_tx_burst, (void *)chan, SCHED_PRIO_SEND))) {
        lune_log(LUNE_CRIT, "failed to add send task on %s: %s", chan->name, ERR_GET_LAST_ERR_STR());
        return ERR_GET_LAST_ERR();
    }

    aggr_enable_chan(chan->acp);
    NET_IF_DPDK_CHAN_SET_UP(chan);
    return 0;
}

static int net_if_dpdk_chan_set_down(net_if_dpdk_chan_t *chan)
{
    NET_IF_DPDK_CHAN_SET_DOWN(chan);
    aggr_disable_chan(chan->acp);
    lune_assert(!sched_del_task(chan->tx_task_id));
    return 0;
}

static int net_if_dpdk_chan_send(net_if_dpdk_chan_t *chan, const unsigned char *buf, unsigned int len)
{
    int i, j, tx_num, zero_copy;
    struct rte_mbuf *mbuf;
    unsigned char *p;
    pbuf_t *pbuf;

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
            lune_log(LUNE_WARN, "failed to allocate tx pktmbuf for %s", chan->name);
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
            if (NET_IF_OPT_IS_HW_TX_CSUM_IPV4(chan->csum_offloads)) {
                mbuf->ol_flags |= PKT_TX_IP_CKSUM;
            }
        }

        switch (PBUF_GET_L4_TYPE(pbuf)) {
        case PBUF_L4_TYPE_TCP:
            if (NET_IF_OPT_IS_HW_TX_CSUM_TCP(chan->csum_offloads)) {
                mbuf->ol_flags |= PKT_TX_TCP_CKSUM;
            }
            break;
        case PBUF_L4_TYPE_UDP:
            if (NET_IF_OPT_IS_HW_TX_CSUM_UDP(chan->csum_offloads)) {
                mbuf->ol_flags |= PKT_TX_UDP_CKSUM;
            }
            break;
        default:
            break;
        }
    }

    NET_IF_DPDK_CAP_PKT_OUT(chan->dpdk_ifp, buf, len);

    if (!zero_copy) {
        p = rte_pktmbuf_mtod(mbuf, unsigned char *);
        memcpy(p, buf, len);
    }
    chan->tx_pkts_burst[chan->tx_offset++] = mbuf;

    if (chan->tx_offset >= NET_IF_DPDK_CHAN_MAX_TX_PKT_BURST) {
        tx_num = rte_eth_tx_burst(chan->port_id,
            chan->txq_id, chan->tx_pkts_burst, NET_IF_DPDK_CHAN_MAX_TX_PKT_BURST);
        if (unlikely(tx_num != NET_IF_DPDK_CHAN_MAX_TX_PKT_BURST)) {
            for (i = 0, j = tx_num; j < NET_IF_DPDK_CHAN_MAX_TX_PKT_BURST; i++, j++) {
                chan->tx_pkts_burst[i] = chan->tx_pkts_burst[j];
            }
            chan->tx_offset = NET_IF_DPDK_CHAN_MAX_TX_PKT_BURST - tx_num;
        } else {
            chan->tx_offset = 0;
        }
    }

    chan->stats.byte_out += len;
    chan->stats.pkt_out++;

    return 0;
}

static int net_if_dpdk_chan_recv(net_if_dpdk_chan_t *chan, const unsigned char **pbuf, unsigned int *plen)
{
    int err;

    if (0 != (err = aggr_chan_recv(chan->acp, pbuf, plen))) {
        return err;
    }

    chan->stats.byte_in += *plen;
    chan->stats.pkt_in++;

    return 0;
}

static void net_if_dpdk_chan_recv_done(net_if_dpdk_chan_t *chan)
{
    aggr_chan_recv_done(chan->acp);
}

static int net_if_dpdk_chan_get_opt(net_if_dpdk_chan_t *chan,
    net_if_opt_en opt, unsigned char *opt_val, unsigned int opt_len)
{
    lune_assert(NULL != opt_val);

    switch (opt) {
    case NET_IF_OPT_GET_HW_CSUM:
        if (opt_len != sizeof(unsigned short)) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        *(unsigned short *)opt_val = chan->csum_offloads;
        break;
    case NET_IF_OPT_GET_MAX_DATA_RATE:
        /*
            always asked while new interface being added, no need to report error
        */
        return -LUNE_ERR_NOT_SUPPORTED;
    case NET_IF_OPT_GET_MTU:
        if (opt_len != sizeof(unsigned short)) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        *(unsigned short *)opt_val = chan->mtu;
        break;
    case NET_IF_OPT_GET_STATS:
        if (opt_len != sizeof(lune_net_if_stats_t)) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        memcpy(opt_val, &chan->stats, sizeof(lune_net_if_stats_t));
        break;
    case NET_IF_OPT_GET_CHAN_ID:
        if (opt_len != sizeof(unsigned int)) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }
        *(unsigned int *)opt_val = aggr_chan_get_id(chan->acp);
        break;
    default:
        return ERR_SET_ERR(LUNE_ERR_NOT_SUPPORTED);
    }

    return 0;
}

static int net_if_dpdk_chan_set_opt(net_if_dpdk_chan_t *chan,
    net_if_opt_en opt,
    const unsigned char *opt_val,
    unsigned int opt_len __attribute__((unused)))
{
    lune_assert(NULL != opt_val);

    switch (opt) {
    case NET_IF_OPT_SET_MTU:
        chan->mtu = *(const unsigned short *)opt_val;
        break;
    case NET_IF_OPT_DISABLE_HW_CSUM:
        lune_log(LUNE_INFO, "checksum offload not supported on %s", chan->name);
        /* fall through */
    default:
        return ERR_SET_ERR(LUNE_ERR_NOT_SUPPORTED);
    }

    return 0;
}

net_if_drv_t g_net_if_drv_dpdk_chan = {
    .type = LUNE_NET_IF_DPDK_CHAN,
    .name = "dpdk channel",
    .add_net_if = (net_if_add_net_if_func_t)net_if_dpdk_chan_add_net_if,
    .del_net_if = (net_if_del_net_if_func_t)net_if_dpdk_chan_del_net_if,
    .is_up = (net_if_is_up_func_t)net_if_dpdk_chan_is_up,
    .set_up = (net_if_set_up_func_t)net_if_dpdk_chan_set_up,
    .set_down = (net_if_set_down_func_t)net_if_dpdk_chan_set_down,
    .send = (net_if_send_func_t)net_if_dpdk_chan_send,
    .send_pkts = NULL,
    .recv = (net_if_recv_func_t)net_if_dpdk_chan_recv,
    .recv_pkts = NULL,
    .recv_done = (net_if_recv_done_func_t)net_if_dpdk_chan_recv_done,
    .recv_fwd_pkt = NULL,
    .recv_free_pkt = NULL,
    .get_opt = (net_if_get_opt_func_t)net_if_dpdk_chan_get_opt,
    .set_opt = (net_if_set_opt_func_t)net_if_dpdk_chan_set_opt,
};
