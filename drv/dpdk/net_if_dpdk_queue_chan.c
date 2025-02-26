/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2024 Lune Reseau, Inc.
 */

#include <rte_ethdev.h>
#include <rte_mbuf.h>

#include "lune/net_if.h"
#include "lune/log.h"
#include "lune/mem.h"
#include "lune/os/linux.h"
#include "lune/time.h"
#include "lune/timer.h"

#include "drv/aggr.h"
#include "drv/dpdk/net_if_dpdk_queue.h"
#include "drv/dpdk/net_if_dpdk_queue_chan.h"
#include "drv/net_if.h"
#include "kernel/sched.h"
#include "lib/ringbuf.h"
#include "net/socket.h"
#include "rt/core.h"
#include "utils/cap.h"

#define NET_IF_DPDK_QUEUE_CHAN_MAX_RECV_PKTS_ATTEMPTS      (5)

#define NET_IF_DPDK_QUEUE_CHAN_MAX_RX_RB_FRM_BURST         (8)

/*
    according to rte_pktmbuf_pool_create:

    The optimum size (in terms of memory usage) for a mempool is
    when n is a power of two minus one: n = (2^q - 1).
*/
#define NET_IF_DPDK_QUEUE_CHAN_MBUF_NUM                    (1024 * 64 - 1)

typedef struct _net_if_dpdk_queue_chan {
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
    unsigned int queue_cnt;
#define NET_IF_DPDK_QUEUE_CHAN_FLAG_ON(chan, flag)         \
    (((net_if_dpdk_queue_chan_t *)(chan))->flags & (flag))
#define NET_IF_DPDK_QUEUE_CHAN_SET_FLAG(chan, flag)        \
    do { ((net_if_dpdk_queue_chan_t *)(chan))->flags |= (flag); } while (0)
#define NET_IF_DPDK_QUEUE_CHAN_CLEAR_FLAG(chan, flag)      \
    do { ((net_if_dpdk_queue_chan_t *)(chan))->flags &= (~flag); } while (0)
#define NET_IF_DPDK_QUEUE_CHAN_FLAG_UP                     0x00000001
#define NET_IF_DPDK_QUEUE_CHAN_IS_UP(chan)                 \
    NET_IF_DPDK_QUEUE_CHAN_FLAG_ON(chan, NET_IF_DPDK_QUEUE_CHAN_FLAG_UP)
#define NET_IF_DPDK_QUEUE_CHAN_SET_UP(chan)                \
    NET_IF_DPDK_QUEUE_CHAN_SET_FLAG(chan, NET_IF_DPDK_QUEUE_CHAN_FLAG_UP)
#define NET_IF_DPDK_QUEUE_CHAN_SET_DOWN(chan)              \
    NET_IF_DPDK_QUEUE_CHAN_CLEAR_FLAG(chan, NET_IF_DPDK_QUEUE_CHAN_FLAG_UP)
    unsigned int flags;
#define NET_IF_DPDK_QUEUE_CHAN_MAX_TX_PKT_BURST            (32)
    struct rte_mbuf *tx_pkts_burst[NET_IF_DPDK_QUEUE_CHAN_MAX_TX_PKT_BURST];
    net_if_t *ai_ifp;
    ringbuf_t **rx_rb_array;
    unsigned int rx_rb_idx;
    unsigned char *rx_rb_curr_frm;
    net_if_dpdk_net_if_t *dpdk_ifp;
} net_if_dpdk_queue_chan_t;

int net_if_dpdk_queue_chan_recv_from_queue(net_if_t *ifp,
    struct rte_mbuf *mbuf, unsigned int chan_idx, unsigned int queue_idx)
{
    ringbuf_t *rx_rb;
    unsigned char *w_buf;
    net_if_dpdk_queue_chan_t *chan;

    chan = (net_if_dpdk_queue_chan_t *)aggr_net_if_get_chan_data(NET_IF_GET_AGGR_NET_IF(ifp), chan_idx);

#ifdef LUNE_DEBUG
    lune_assert(queue_idx < chan->queue_cnt);
#endif

    rx_rb = chan->rx_rb_array[queue_idx];
    if (NULL == (w_buf = ringbuf_get_write_frm(rx_rb, AGGR_CHAN_RX_RB_PKT_SIZE))) {
        lune_log_once(LUNE_INFO, "failed to send aggregated packet to %s: %s",
            chan->name, ERR_GET_ERR_STR(ERR_SET_ERR(LUNE_ERR_BUF_FULL)));
        return ERR_GET_LAST_ERR();
    }

    AGGR_CHAN_BUILD_RX_PTR_HDR(w_buf, AGGR_CHAN_RX_RB_PKT_SIZE, mbuf);
    ringbuf_write_frm_done(rx_rb, w_buf);

    return 0;
}

static int net_if_dpdk_queue_chan_init_chan(net_if_dpdk_queue_chan_t *chan,
    const char *name, net_if_t *ifp)
{
    int err;
    unsigned int i, j;
    char tmp_name[LUNE_MAX_SHORT_NAME_BUF_LEN];
    net_if_t *ai_ifp;
    unsigned short chan_id, queue_id;

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
    if (ai_ifp->type != LUNE_NET_IF_DPDK_QUEUE) {
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

    chan->tx_offset = 0;
    chan->tx_task_id = LUNE_INVALID_ID;
    chan->flags = 0;
    chan_id = (unsigned short)aggr_chan_get_id(chan->acp);
    queue_id = (unsigned short)net_if_dpdk_queue_get_queue_id(ai_ifp->net_if_data);
    chan->txq_id =
        queue_id * (unsigned short)aggr_chan_get_aggr_chan_num(chan->acp) + chan_id;
    for (i = 0; i < NET_IF_DPDK_QUEUE_CHAN_MAX_TX_PKT_BURST; i++) {
        chan->tx_pkts_burst[i] = NULL;
    }

    sprintf(tmp_name, "dpdk mbuf pool %d", CORE_GET_ID());
    if (NULL == g_net_if_dpdk_send_mbuf_pool) {
        if (NULL == (g_net_if_dpdk_send_mbuf_pool = rte_pktmbuf_pool_create(tmp_name,
            NET_IF_DPDK_QUEUE_CHAN_MBUF_NUM,
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

    chan->queue_cnt = net_if_dpdk_queue_get_queue_num(ai_ifp->net_if_data);
    if (NULL == (chan->rx_rb_array =
        lune_malloc_mt(sizeof(ringbuf_t *) * chan->queue_cnt))) {
        goto ERR_2;
    }

    for (i = 0; i < chan->queue_cnt; i++) {
        sprintf(tmp_name, "rx ringbuf %s chan %d", name, i);
        if (NULL == (chan->rx_rb_array[i] = ringbuf_create_buf(tmp_name,
            AGGR_CHAN_RX_RB_PKT_NUM, AGGR_CHAN_RX_RB_PKT_SIZE))) {
            goto ERR_3;
        }
    }

    chan->rx_rb_idx = chan->queue_cnt;
    chan->rx_rb_curr_frm = NULL;
    lune_assert(NULL != (chan->dpdk_ifp =
        net_if_dpdk_queue_get_dpdk_net_if(ai_ifp->net_if_data)));

    chan->ai_ifp = ai_ifp;
    net_if_hold(ai_ifp);

    return 0;

ERR_3:
    for (j = 0; j < i; j++) {
        ringbuf_delete_buf(chan->rx_rb_array[j]);
    }

    lune_free_mt(chan->rx_rb_array);
    chan->rx_rb_array = NULL;

ERR_2:
    lune_assert(!aggr_del_chan(chan->acp));

ERR_1:
    return err;
}

static int net_if_dpdk_queue_chan_add_net_if(net_if_t *ifp,
    const char *name, const void *conf_val, unsigned int conf_len, void **pdata)
{
    net_if_dpdk_queue_chan_t *chan;
    int err;

    if (conf_val != NULL || conf_len != 0) {
        err = ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        goto ERR_1;
    }

    if (NULL == (chan = lune_malloc(sizeof(net_if_dpdk_queue_chan_t)))) {
        err = ERR_GET_LAST_ERR();
        goto ERR_1;
    }

    if (0 != (err = net_if_dpdk_queue_chan_init_chan(chan, name, ifp))) {
        goto ERR_2;
    }

    *pdata = chan;

    return 0;

ERR_2:
    lune_free(chan);

ERR_1:
    return err;
}

static int net_if_dpdk_queue_chan_del_net_if(net_if_dpdk_queue_chan_t *chan)
{
    int err;
    unsigned int i;

    lune_assert(NULL != chan->acp);
    lune_assert(NULL != chan->ai_ifp);

    net_if_put(chan->ai_ifp);

    lune_assert(chan->rx_rb_idx == chan->queue_cnt);
    lune_assert(NULL == chan->rx_rb_curr_frm);

    for (i = 0; i < chan->queue_cnt; i++) {
        ringbuf_delete_buf(chan->rx_rb_array[i]);
    }

    lune_free_mt(chan->rx_rb_array);
    chan->rx_rb_array = NULL;

    if (0 != (err = aggr_del_chan(chan->acp))) {
        return err;
    }

    lune_free(chan);
    return 0;
}

static int net_if_dpdk_queue_chan_is_up(net_if_dpdk_queue_chan_t *chan)
{
    return NET_IF_DPDK_QUEUE_CHAN_IS_UP(chan);
}

static void net_if_dpdk_queue_chan_send_tx_burst(net_if_dpdk_queue_chan_t *chan)
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

static int net_if_dpdk_queue_chan_set_up(net_if_dpdk_queue_chan_t *chan)
{
    lune_assert(NULL != chan->ai_ifp);

    if (!NET_IF_IS_ACTIVE(chan->ai_ifp)) {
        /* aggregated interface should be enabled first */
        return ERR_SET_ERR(LUNE_ERR_NET_IF_AGGR_NOT_ENABLED);
    }

    if (LUNE_INVALID_ID == (chan->tx_task_id = sched_add_task(chan->name,
        (lune_task_func_t)net_if_dpdk_queue_chan_send_tx_burst, (void *)chan, SCHED_PRIO_SEND))) {
        lune_log(LUNE_CRIT, "failed to add send task on %s: %s", chan->name, ERR_GET_LAST_ERR_STR());
        return ERR_GET_LAST_ERR();
    }

    aggr_enable_chan(chan->acp);
    NET_IF_DPDK_QUEUE_CHAN_SET_UP(chan);
    return 0;
}

static int net_if_dpdk_queue_chan_set_down(net_if_dpdk_queue_chan_t *chan)
{
    NET_IF_DPDK_QUEUE_CHAN_SET_DOWN(chan);
    aggr_disable_chan(chan->acp);

    lune_assert(LUNE_INVALID_ID != chan->tx_task_id);
    lune_assert(!sched_del_task(chan->tx_task_id));
    chan->tx_task_id = LUNE_INVALID_ID;

    return 0;
}

static int net_if_dpdk_queue_chan_send(net_if_dpdk_queue_chan_t *chan,
    const unsigned char *buf, unsigned int len)
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

    NET_IF_CAP_PKT(chan->ai_ifp, buf, len);
    NET_IF_DPDK_CAP_PKT_OUT(chan->dpdk_ifp, buf, len);

    if (!zero_copy) {
        p = rte_pktmbuf_mtod(mbuf, unsigned char *);
        memcpy(p, buf, len);
    }
    chan->tx_pkts_burst[chan->tx_offset++] = mbuf;

    if (chan->tx_offset >= NET_IF_DPDK_QUEUE_CHAN_MAX_TX_PKT_BURST) {
        tx_num = rte_eth_tx_burst(chan->port_id,
            chan->txq_id, chan->tx_pkts_burst, NET_IF_DPDK_QUEUE_CHAN_MAX_TX_PKT_BURST);
        if (unlikely(tx_num != NET_IF_DPDK_QUEUE_CHAN_MAX_TX_PKT_BURST)) {
            for (i = 0, j = tx_num; j < NET_IF_DPDK_QUEUE_CHAN_MAX_TX_PKT_BURST; i++, j++) {
                chan->tx_pkts_burst[i] = chan->tx_pkts_burst[j];
            }
            chan->tx_offset = NET_IF_DPDK_QUEUE_CHAN_MAX_TX_PKT_BURST - tx_num;
        } else {
            chan->tx_offset = 0;
        }
    }

    chan->stats.byte_out += len;
    chan->stats.pkt_out++;

    return 0;
}

static int net_if_dpdk_queue_chan_recv_pkts(net_if_dpdk_queue_chan_t *chan)
{
    int err, last_err = 0;
    unsigned int i, j, attempts, frm_cnt;
    struct rte_mbuf *mbuf;
    ringbuf_frm_t frms_burst[NET_IF_DPDK_QUEUE_CHAN_MAX_RX_RB_FRM_BURST];

#ifdef LUNE_DEBUG
    lune_assert(!NET_IF_IS_AGGR(chan->ifp));
#endif

    attempts = 0;
    while (attempts++ < NET_IF_DPDK_QUEUE_CHAN_MAX_RECV_PKTS_ATTEMPTS) {
        for (i = 0; i < chan->queue_cnt; i++) {
            if (0 != (frm_cnt = ringbuf_get_read_frm_burst(chan->rx_rb_array[i],
                frms_burst, NET_IF_DPDK_QUEUE_CHAN_MAX_RX_RB_FRM_BURST))) {
                for (j = 0; j < frm_cnt; j++) {
                    mbuf = (struct rte_mbuf *)AGGR_CHAN_GET_RX_PTR(frms_burst[j].buf);

                    chan->rx_rb_idx = i;
                    chan->rx_rb_curr_frm = frms_burst[j].buf;

                    if (0 != (err = net_if_process_single_net_if_recv_func(chan->ifp,
                        rte_pktmbuf_mtod(mbuf, unsigned char *),
                        rte_pktmbuf_data_len(mbuf), 0))) {
                        last_err = err;
                    }

#ifdef LUNE_DEBUG
                    lune_assert(chan->rx_rb_idx == chan->queue_cnt);
                    lune_assert(NULL == chan->rx_rb_curr_frm);
#endif

                    chan->stats.byte_in += rte_pktmbuf_data_len(mbuf);
                    chan->stats.pkt_in++;
                }
            }
        }
    }

    return last_err;
}

static void net_if_dpdk_queue_chan_recv_done(net_if_dpdk_queue_chan_t *chan)
{
    aggr_chan_recv_pkts_done(chan->acp, chan->rx_rb_curr_frm);
    ringbuf_read_frm_done(chan->rx_rb_array[chan->rx_rb_idx],
        chan->rx_rb_curr_frm);
    chan->rx_rb_idx = chan->queue_cnt;
    chan->rx_rb_curr_frm = NULL;
}

static int net_if_dpdk_queue_chan_get_opt(net_if_dpdk_queue_chan_t *chan,
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

static int net_if_dpdk_queue_chan_set_opt(net_if_dpdk_queue_chan_t *chan,
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

net_if_drv_t g_net_if_drv_dpdk_queue_chan = {
    .type = LUNE_NET_IF_DPDK_QUEUE_CHAN,
    .name = "dpdk channel",
    .add_net_if = (net_if_add_net_if_func_t)net_if_dpdk_queue_chan_add_net_if,
    .del_net_if = (net_if_del_net_if_func_t)net_if_dpdk_queue_chan_del_net_if,
    .is_up = (net_if_is_up_func_t)net_if_dpdk_queue_chan_is_up,
    .set_up = (net_if_set_up_func_t)net_if_dpdk_queue_chan_set_up,
    .set_down = (net_if_set_down_func_t)net_if_dpdk_queue_chan_set_down,
    .send = (net_if_send_func_t)net_if_dpdk_queue_chan_send,
    .send_pkts = NULL,
    .recv = NULL,
    .recv_pkts = (net_if_recv_pkts_func_t)net_if_dpdk_queue_chan_recv_pkts,
    .recv_done = (net_if_recv_done_func_t)net_if_dpdk_queue_chan_recv_done,
    .recv_fwd_pkt = NULL,
    .recv_free_pkt = NULL,
    .get_opt = (net_if_get_opt_func_t)net_if_dpdk_queue_chan_get_opt,
    .set_opt = (net_if_set_opt_func_t)net_if_dpdk_queue_chan_set_opt,
};
