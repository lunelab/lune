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
#include "drv/dpdk/net_if_dpdk_queue.h"
#include "drv/dpdk/net_if_dpdk_queue_chan.h"
#include "drv/net_if.h"
#include "lib/ringbuf.h"
#include "kernel/sched.h"
#include "kernel/timer.h"
#include "net/socket.h"
#include "rt/core.h"
#include "utils/net_if_dpdk_cap.h"

#define NET_IF_DPDK_QUEUE_MAX_RECV_PKTS_ATTEMPTS        (3)

#define NET_IF_DPDK_QUEUE_MAX_RX_RB_FRM_BURST           (8)

#define NET_IF_DPDK_QUEUE_RXQ_IS_POW2_NUM(n)            IS_POW2_NUM(n)

#define NET_IF_DPDK_QUEUE_IS_DPDK_QUEUE_CHAN(queue)     \
    (((net_if_dpdk_queue_t *)(queue))->chan_num != 0)

/*
    according to rte_pktmbuf_pool_create:

    The optimum size (in terms of memory usage) for a mempool is 
    when n is a power of two minus one: n = (2^q - 1).
*/
#define NET_IF_DPDK_QUEUE_MBUF_NUM                      (1024 * 64 - 1)

/*
    3 interface topologies is supported by dpdk queue driver:
    1. Non-aggregated interface
    2. Aggregated interface aggregating LUNE_NET_IF_DPDK_QUEUE_CHAN interfaces
    3. Aggregated interface aggregating LUNE_NET_IF_CHAN interfaces only if 2 not
       available (e.g., limit of tx queue)

    Topo 3 may be removed afterwards if unneeded
*/

typedef struct _net_if_dpdk_queue_sib_rx_rb_hdr {
#define NET_IF_DPDK_QUEUE_SIB_RX_RB_TYPE_PTR            (0)
    unsigned int type;
    unsigned int len;
    unsigned char val[0];
} net_if_dpdk_queue_sib_rx_rb_hdr_t;

typedef struct _net_if_dpdk_queue {
    char name[LUNE_MAX_SHORT_NAME_BUF_LEN];
    net_if_t *qifp;
    net_if_dpdk_net_if_t *ifp;
    lune_net_if_stats_t stats;
    unsigned short rxq_id;
    unsigned short txq_id;
    unsigned int tx_task_id;
    unsigned short rx_offset;
    unsigned short tx_offset;
#define NET_IF_DPDK_QUEUE_FLAG_ON(queue, flag)          \
    (((net_if_dpdk_queue_t *)(queue))->flags & (flag))
#define NET_IF_DPDK_QUEUE_SET_FLAG(queue, flag)         \
    do { ((net_if_dpdk_queue_t *)(queue))->flags |= (flag); } while (0)
#define NET_IF_DPDK_QUEUE_CLEAR_FLAG(queue, flag)       \
    do { ((net_if_dpdk_queue_t *)(queue))->flags &= (~flag); } while (0)
#define NET_IF_DPDK_QUEUE_FLAG_UP                       0x00000001
#define NET_IF_DPDK_QUEUE_IS_UP(queue)                  \
    NET_IF_DPDK_QUEUE_FLAG_ON(queue, NET_IF_DPDK_QUEUE_FLAG_UP)
#define NET_IF_DPDK_QUEUE_SET_UP(queue)                 \
    NET_IF_DPDK_QUEUE_SET_FLAG(queue, NET_IF_DPDK_QUEUE_FLAG_UP)
#define NET_IF_DPDK_QUEUE_SET_DOWN(queue)               \
    NET_IF_DPDK_QUEUE_CLEAR_FLAG(queue, NET_IF_DPDK_QUEUE_FLAG_UP)
#define NET_IF_DPDK_QUEUE_FLAG_SIB_RX_RB_PKT            0x00000002
#define NET_IF_DPDK_QUEUE_IS_SIB_RX_RB_PKT(queue)       \
    NET_IF_DPDK_QUEUE_FLAG_ON(queue, NET_IF_DPDK_QUEUE_FLAG_SIB_RX_RB_PKT)
#define NET_IF_DPDK_QUEUE_SET_SIB_RX_RB_PKT(queue)      \
    NET_IF_DPDK_QUEUE_SET_FLAG(queue, NET_IF_DPDK_QUEUE_FLAG_SIB_RX_RB_PKT)
#define NET_IF_DPDK_QUEUE_CLEAR_SIB_RX_RB_PKT(queue)    \
    NET_IF_DPDK_QUEUE_CLEAR_FLAG(queue, NET_IF_DPDK_QUEUE_FLAG_SIB_RX_RB_PKT)
    unsigned int flags;
#define NET_IF_DPDK_QUEUE_MAX_RX_PKT_BURST              (32)
    struct rte_mbuf *rx_pkts_burst[NET_IF_DPDK_QUEUE_MAX_RX_PKT_BURST];
#define NET_IF_DPDK_QUEUE_MAX_TX_PKT_BURST              (32)
    struct rte_mbuf *tx_pkts_burst[NET_IF_DPDK_QUEUE_MAX_TX_PKT_BURST];
    unsigned long long pkt_in_ipv4_csum_err;
    unsigned long long pkt_in_l4_csum_err;
#define NET_IF_DPDK_QUEUE_SIB_RX_RB_PKT_NUM             (4096)
#define NET_IF_DPDK_QUEUE_SIB_RX_RB_PKT_SIZE            \
    (sizeof(net_if_dpdk_queue_sib_rx_rb_hdr_t) + sizeof(struct rte_mbuf **))
    void **rx_rb_array;
    unsigned int chan_num;                              /* non-zero only if txq_num greater than rxq_num */
    unsigned int sib_rx_rb_idx;
    net_if_dpdk_queue_sib_rx_rb_hdr_t *sib_rx_rb_hdr;
#ifdef LUNE_DEBUG
    unsigned int prof_local_pkt_in;
    unsigned int prof_local_pkt_dropped;
    unsigned int prof_dist_pkt_in;
    unsigned int prof_dist_pkt_out;
    lune_timer_t prof_stats_tmr;
#endif
} net_if_dpdk_queue_t;

#ifdef LUNE_DEBUG
static void net_if_dpdk_queue_prof_stats_timer_func(net_if_dpdk_queue_t *queue)
{
    lune_log(LUNE_DBG, "%s profile statistics: local_pkt_in %d local_pkt_dropped %d"
        " dist_pkt_in %d dist_pkt_out %d",
        queue->name,
        queue->prof_local_pkt_in,
        queue->prof_local_pkt_dropped,
        queue->prof_dist_pkt_in,
        queue->prof_dist_pkt_out);
}
#endif

int net_if_dpdk_queue_is_valid_chan_type(void *queue, lune_net_if_type_en type)
{
    net_if_dpdk_net_if_t *ifp = ((net_if_dpdk_queue_t *)queue)->ifp;
    net_if_t *qifp = ((net_if_dpdk_queue_t *)queue)->qifp;

    if (unlikely(NULL == NET_IF_GET_AGGR_NET_IF(qifp))) {
        /* not aggregated interface */
        return 0;
    }

    if (ifp->rxq_num == ifp->txq_num
        && LUNE_NET_IF_CHAN == type) {
        return 1;
    }

    if (ifp->rxq_num != ifp->txq_num
        && LUNE_NET_IF_DPDK_QUEUE_CHAN == type) {
#ifdef LUNE_DEBUG
        unsigned short chan_num = AGGR_NET_IF_GET_TOTAL_CHAN_NUM(NET_IF_GET_AGGR_NET_IF(qifp));
        lune_assert((ifp->txq_num / ifp->rxq_num) == chan_num);
#endif
        return 1;
    }

    return 0;
}

int net_if_dpdk_queue_is_valid_chan_num(void *queue, unsigned int chan_num)
{
    net_if_dpdk_queue_t *q = (net_if_dpdk_queue_t *)queue, *sib_queue;
    int i;

    if (q->chan_num != 0) {
        /* txq_num greater than rxq_num */
        return q->chan_num == chan_num ? 1 : 0;
    }

    /* txq_num equals to rxq_num */
    for (i = 0; i < q->ifp->rxq_num; i++) {
        if (i == q->rxq_id) {
            continue;
        }

        if (NULL != q->ifp->queue_array[i]) {
            sib_queue = q->ifp->queue_array[i];
            if (!NET_IF_IS_AGGR(sib_queue->qifp)
                /* chan_num must be identical to number of channels on all other queues */
                || AGGR_NET_IF_GET_TOTAL_CHAN_NUM(NET_IF_GET_AGGR_NET_IF(sib_queue->qifp)) != chan_num
                /* txq_num must equals to rxq_num on all other queues, i.e., chan_num = 0 */
                || sib_queue->chan_num != chan_num) {
                return 0;
            } else {
                return 1;
            }
        }
    }

    /* first queue */
    return 1;
}

unsigned int net_if_dpdk_queue_get_queue_id(void *queue)
{
    return ((net_if_dpdk_queue_t *)queue)->rxq_id;
}

unsigned int net_if_dpdk_queue_get_queue_num(void *queue)
{
    return ((net_if_dpdk_queue_t *)queue)->ifp->rxq_num;
}

net_if_dpdk_net_if_t *net_if_dpdk_queue_get_dpdk_net_if(void *queue)
{
    return ((net_if_dpdk_queue_t *)queue)->ifp;
}

static int net_if_dpdk_queue_init_queue(net_if_dpdk_queue_t *queue,
    const lune_net_if_dpdk_queue_conf_t *conf, const char *name)
{
    int err, first;
    unsigned int i, j;
    char tmp_name[LUNE_MAX_SHORT_NAME_BUF_LEN];
    char *p;
    net_if_dpdk_net_if_t *ifp;
    struct rte_eth_rxconf rx_conf;
    unsigned short queue_id;

    if (NULL == (p = strrchr(name, '/'))) {
        err = ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        goto ERR_1;
    }

    queue_id = atoi(p + 1);
    if (queue_id >= conf->rxq_num) {
        err = ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        goto ERR_1;
    }

    strcpy(queue->name, name);
    strncpy(tmp_name, name, (unsigned int)(p - name));
    tmp_name[p - name] = '\0';

    pthread_spin_lock(&g_net_if_dpdk_lock);
    if (NULL == (ifp = net_if_dpdk_get_dpdk_net_if_by_name(tmp_name))) {
        first = 1;

        if (0 != (conf->txq_num % conf->rxq_num)
            || (conf->txq_num / conf->rxq_num) > AGGR_NET_IF_MAX_AGGR_PER_NET_IF_NUM) {
            err = ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
            goto ERR_2;
        }

        if (!NET_IF_DPDK_QUEUE_RXQ_IS_POW2_NUM(conf->rxq_num)) {
            /* packet distribution may not be expected but keep going */
            lune_log(LUNE_INFO, "creating %d dpdk receive queues for %s", conf->rxq_num, name);
        }

        if (NULL == (ifp = net_if_dpdk_add_dpdk_net_if(tmp_name,
            conf->rxq_num, conf->txq_num, conf->rss_type))) {
            err = ERR_GET_LAST_ERR();
            goto ERR_2;
        }
    } else {
        pthread_spin_unlock(&g_net_if_dpdk_lock);

        first = 0;

        pthread_spin_lock(&ifp->lock);
        if (ifp->rxq_num != conf->rxq_num
            || ifp->txq_num != conf->txq_num
            || ifp->rss_type != conf->rss_type) {
            err = ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
            goto ERR_2;
        }

        if (ifp->queue_array[queue_id] != NULL) {
            err = ERR_SET_ERR(LUNE_ERR_ALREADY_EXIST);
            goto ERR_2;
        }
    }

    queue->ifp = ifp;
    memset(&queue->stats, 0x00, sizeof(lune_net_if_stats_t));
    queue->rxq_id = queue->txq_id = queue_id;
    queue->flags = 0;

    for (i = 0; i < NET_IF_DPDK_QUEUE_MAX_RX_PKT_BURST; i++) {
        queue->rx_pkts_burst[i] = NULL;
    }

    for (i = 0; i < NET_IF_DPDK_QUEUE_MAX_TX_PKT_BURST; i++) {
        queue->tx_pkts_burst[i] = NULL;
    }

    sprintf(tmp_name, "dpdk mbuf pool %d", CORE_GET_ID());
    if (NULL == g_net_if_dpdk_send_mbuf_pool) {
        if (NULL == (g_net_if_dpdk_send_mbuf_pool = rte_pktmbuf_pool_create(tmp_name,
            NET_IF_DPDK_QUEUE_MBUF_NUM,
            32,
            0,
            RTE_MBUF_DEFAULT_BUF_SIZE,
            rte_socket_id()))) {
            lune_log(LUNE_WARN, "failed to create mbuf pool for %s: %s", name, rte_strerror(rte_errno));
            err = ERR_SET_ERR(LUNE_ERR_NET_IF_INTERNAL);
            goto ERR_2;
        }
    }

    if (conf->rxq_num == conf->txq_num) {
        queue->chan_num = 0;
        if (NULL == (queue->rx_rb_array = lune_malloc_mt(sizeof(void *) * conf->rxq_num))) {
            err = ERR_SET_ERR(LUNE_ERR_NO_MEM);
            goto ERR_2;
        }

        for (i = 0; i < conf->rxq_num; i++) {
            sprintf(tmp_name, "rx ringbuf %s queue %d", name, i);
            if (NULL == (queue->rx_rb_array[i] = ringbuf_create_buf(tmp_name,
                NET_IF_DPDK_QUEUE_SIB_RX_RB_PKT_NUM, NET_IF_DPDK_QUEUE_SIB_RX_RB_PKT_SIZE))) {
                err = ERR_GET_LAST_ERR();
                goto ERR_3;
            }
        }
    } else {
        queue->chan_num = conf->txq_num / conf->rxq_num;
        queue->rx_rb_array = NULL;
    }

    queue->sib_rx_rb_idx = ifp->rxq_num;
    queue->sib_rx_rb_hdr = NULL;
#ifdef LUNE_DEBUG
    queue->prof_local_pkt_in = queue->prof_local_pkt_dropped = queue->prof_dist_pkt_in = queue->prof_dist_pkt_out = 0;
    timer_init_timer(&queue->prof_stats_tmr,
        LUNE_TIMER_RECURRING,
        LUNE_TIMER_RES_DEFAULT,
        (lune_timer_func_t)net_if_dpdk_queue_prof_stats_timer_func,
        queue);
#endif

    rx_conf = ifp->dev_info.default_rxconf;
    rx_conf.offloads = ifp->port_conf.rxmode.offloads;
    if (0 != (err = rte_eth_rx_queue_setup(ifp->port_id, queue->rxq_id, ifp->rxd_num,
        rte_eth_dev_socket_id(ifp->port_id), &rx_conf, g_net_if_dpdk_send_mbuf_pool))) {
        lune_log(LUNE_WARN, "failed to setup rx queue on %s: %d", name, err);
        err = ERR_SET_ERR(LUNE_ERR_SYS_ERR);
        goto ERR_3;
    }

    ifp->queue_cnt++;
    ifp->queue_array[queue_id] = (void *)queue;

    if (first) {
        pthread_spin_unlock(&g_net_if_dpdk_lock);
    } else {
        pthread_spin_unlock(&ifp->lock);
    }

    return 0;

ERR_3:
    if (NULL != queue->rx_rb_array) {
        for (j = 0; j < i; j++) {
            ringbuf_delete_buf(queue->rx_rb_array[j]);
        }
        lune_free_mt(queue->rx_rb_array);
        queue->rx_rb_array = NULL;
    }

ERR_2:
    if (first) {
        pthread_spin_unlock(&g_net_if_dpdk_lock);
    } else {
        pthread_spin_unlock(&ifp->lock);
    }

ERR_1:
    return err;
}

static void net_if_dpdk_queue_cleanup_queue(net_if_dpdk_queue_t *queue)
{
    net_if_dpdk_net_if_t *ifp = queue->ifp;
    unsigned int i;
    unsigned short rxq_num = ifp->rxq_num;

    lune_assert(NULL == queue->sib_rx_rb_hdr);
    lune_assert(rxq_num == queue->sib_rx_rb_idx);

    pthread_spin_lock(&ifp->lock);
    lune_assert(NULL != ifp->queue_array[queue->rxq_id]);
    ifp->queue_array[queue->rxq_id] = NULL;
    --ifp->queue_cnt;
    if (0 == ifp->queue_cnt) {
        pthread_spin_unlock(&ifp->lock);
        pthread_spin_lock(&g_net_if_dpdk_lock);
        net_if_dpdk_del_dpdk_net_if(ifp);
        pthread_spin_unlock(&g_net_if_dpdk_lock);
    } else {
        pthread_spin_unlock(&ifp->lock);
    }

    if (NULL != queue->rx_rb_array) {
        for (i = 0; i < rxq_num; i++) {
            ringbuf_delete_buf(queue->rx_rb_array[i]);
        }
        lune_free_mt(queue->rx_rb_array);
        queue->rx_rb_array = NULL;
    }
}

static int net_if_dpdk_queue_add_net_if(net_if_t *ifp,
    const char *name, const void *conf_val, unsigned int conf_len, void **pdata)
{
    const lune_net_if_dpdk_queue_conf_t *conf;
    net_if_dpdk_queue_t *queue;
    int err;

    if (NULL == conf_val || conf_len != sizeof(lune_net_if_dpdk_queue_conf_t)) {
        err = ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        goto ERR_1;
    }

    conf = (const lune_net_if_dpdk_queue_conf_t *)conf_val;
    if (conf->rss_type < LUNE_NET_IF_DPDK_RSS_TYPE_L3_NONE
        || conf->rss_type >= LUNE_NET_IF_DPDK_RSS_TYPE_MAX) {
        err = ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        goto ERR_1;
    }

    if (conf->rxq_num > NET_IF_DPDK_MAX_QUEUE_NUM) {
        err = ERR_SET_ERR(LUNE_ERR_EXCEED_LIMITS);
        goto ERR_1;
    }

    if (NULL == (queue = lune_malloc(sizeof(net_if_dpdk_queue_t)))) {
        err = ERR_GET_LAST_ERR();
        goto ERR_1;
    }

    if (0 != (err = net_if_dpdk_queue_init_queue(queue, conf, name))) {
        goto ERR_2;
    }

    queue->qifp = ifp;

    *pdata = queue;

    return 0;

ERR_2:
    lune_free(queue);

ERR_1:
    return err;
}

static int net_if_dpdk_queue_del_net_if(net_if_dpdk_queue_t *queue)
{
    net_if_dpdk_queue_cleanup_queue(queue);
    lune_free(queue);
    return 0;
}

static int net_if_dpdk_queue_is_up(net_if_dpdk_queue_t *queue)
{
    return NET_IF_DPDK_QUEUE_IS_UP(queue);
}

static void net_if_dpdk_queue_send_tx_burst(net_if_dpdk_queue_t *queue)
{
    int i, j;
    unsigned int tx_num;

    if (likely(queue->tx_offset > 0)) {
        tx_num = rte_eth_tx_burst(queue->ifp->port_id,
            queue->txq_id, queue->tx_pkts_burst, queue->tx_offset);
        if (unlikely(tx_num != queue->tx_offset)) {
            for (i = 0, j = tx_num; j < queue->tx_offset; i++, j++) {
                queue->tx_pkts_burst[i] = queue->tx_pkts_burst[j];
            }
            queue->tx_offset = queue->tx_offset - tx_num;
        } else {
            queue->tx_offset = 0;
        }
    }
}

static int net_if_dpdk_queue_set_up(net_if_dpdk_queue_t *queue)
{
    int err;
    net_if_dpdk_net_if_t *ifp = queue->ifp;

    queue->tx_task_id = LUNE_INVALID_ID;
    queue->pkt_in_ipv4_csum_err = queue->pkt_in_l4_csum_err = 0;
    queue->rx_offset = queue->tx_offset = 0;

    if (ifp->rxq_num == ifp->txq_num) {
        if (LUNE_INVALID_ID == (queue->tx_task_id = sched_add_task(ifp->name,
            (lune_task_func_t)net_if_dpdk_queue_send_tx_burst, (void *)queue, SCHED_PRIO_SEND))) {
            lune_log(LUNE_CRIT, "failed to add send task on %s: %s", ifp->name, ERR_GET_LAST_ERR_STR());
            goto ERR_1;
        }
    }

    pthread_spin_lock(&ifp->lock);
    if (ifp->queue_cnt < ifp->rxq_num) {
        /* not all dpdk queues been added */
        pthread_spin_unlock(&ifp->lock);
        ERR_SET_ERR(LUNE_ERR_NOT_ADDED);
        goto ERR_1;
    }

    if (!NET_IF_DPDK_IS_STARTED(ifp)) {
        struct rte_eth_rss_conf local_rss_conf;

        /* start dpdk interface since first queue being enabled */
        if (0 != (err = rte_eth_dev_start(ifp->port_id))) {
            lune_log(LUNE_CRIT, "failed to start %s: %d", ifp->name, err);
            ERR_SET_ERR(LUNE_ERR_NET_IF_INTERNAL);
            pthread_spin_unlock(&ifp->lock);
            goto ERR_2;
        }

        local_rss_conf = ifp->port_conf.rx_adv_conf.rss_conf;
        local_rss_conf.rss_hf = (ETH_RSS_IP | (LUNE_NET_IF_DPDK_RSS_TYPE_L3_DST == ifp->rss_type
            ? ETH_RSS_L3_DST_ONLY : ETH_RSS_L3_SRC_ONLY)) & ifp->dev_info.flow_type_rss_offloads;
        if (0 != (err = rte_eth_dev_rss_hash_update(ifp->port_id, &local_rss_conf))) {
            lune_log(LUNE_CRIT, "failed to update RSS hash on %s: %d", ifp->name, err);
            goto ERR_3;
        }

        if (0 != (err = rte_eth_promiscuous_enable(ifp->port_id))) {
            lune_log(LUNE_CRIT, "failed to set promiscuous mode on %s: %d", ifp->name, err);
            ERR_SET_ERR(LUNE_ERR_NET_IF_INTERNAL);
            pthread_spin_unlock(&ifp->lock);
            goto ERR_3;
        }

        NET_IF_DPDK_SET_START(ifp);

        lune_assert(0 == ifp->queue_enabled_cnt);
    }

    ifp->queue_enabled_cnt++;

    pthread_spin_unlock(&ifp->lock);

#ifdef LUNE_DEBUG
    timer_add_timer(&queue->prof_stats_tmr, 1 * LUNE_TIME_SECOND);
#endif

    NET_IF_DPDK_QUEUE_SET_UP(queue);
    return 0;

ERR_3:
    rte_eth_dev_stop(ifp->port_id);

ERR_2:
    if (queue->tx_task_id != LUNE_INVALID_ID) {
        lune_assert(!sched_del_task(queue->tx_task_id));
        queue->tx_task_id = LUNE_INVALID_ID;
    }

ERR_1:
    return ERR_GET_LAST_ERR();
}

static int net_if_dpdk_queue_set_down(net_if_dpdk_queue_t *queue)
{
    net_if_dpdk_net_if_t *ifp = queue->ifp;

#ifdef LUNE_DEBUG
    timer_del_timer(&queue->prof_stats_tmr);
#endif

    pthread_spin_lock(&ifp->lock);
    if (NET_IF_DPDK_IS_CAP_ENABLED(ifp)) {
        /*
            stop packet capture once interface disabled
        */
        net_if_dpdk_cap_stop(ifp->net_if_dpdk_cap);
        ifp->net_if_dpdk_cap = NULL;
    }

    lune_assert(NET_IF_DPDK_IS_STARTED(ifp));

    ifp->queue_enabled_cnt--;
    if (0 == ifp->queue_enabled_cnt) {
        /* stop dpdk interface when last queue being disabled */
        rte_eth_dev_stop(ifp->port_id);
        NET_IF_DPDK_SET_STOP(ifp);
    }
    pthread_spin_unlock(&ifp->lock);

    if (queue->tx_task_id != LUNE_INVALID_ID) {
        lune_assert(!sched_del_task(queue->tx_task_id));
        queue->tx_task_id = LUNE_INVALID_ID;
    }
    queue->pkt_in_ipv4_csum_err = queue->pkt_in_l4_csum_err = 0;
    queue->rx_offset = queue->tx_offset = 0;

    NET_IF_DPDK_QUEUE_SET_DOWN(queue);
    return 0;
}

static int net_if_dpdk_queue_send(net_if_dpdk_queue_t *queue, const unsigned char *buf, unsigned int len)
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
            lune_log(LUNE_WARN, "failed to allocate tx pktmbuf for %s", queue->ifp->name);
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
            if (queue->ifp->port_conf.txmode.offloads & DEV_TX_OFFLOAD_IPV4_CKSUM) {
                mbuf->ol_flags |= PKT_TX_IP_CKSUM;
            }
        }

        switch (PBUF_GET_L4_TYPE(pbuf)) {
        case PBUF_L4_TYPE_TCP:
            if (queue->ifp->port_conf.txmode.offloads & DEV_TX_OFFLOAD_TCP_CKSUM) {
                mbuf->ol_flags |= PKT_TX_TCP_CKSUM;
            }
            break;
        case PBUF_L4_TYPE_UDP:
            if (queue->ifp->port_conf.txmode.offloads & DEV_TX_OFFLOAD_UDP_CKSUM) {
                mbuf->ol_flags |= PKT_TX_UDP_CKSUM;
            }
            break;
        default:
            break;
        }
    }

    NET_IF_DPDK_CAP_PKT_OUT(queue->ifp, buf, len);

    if (!zero_copy) {
        p = rte_pktmbuf_mtod(mbuf, unsigned char *);
        memcpy(p, buf, len);
    }
    queue->tx_pkts_burst[queue->tx_offset++] = mbuf;

    if (queue->tx_offset >= NET_IF_DPDK_QUEUE_MAX_TX_PKT_BURST) {
        tx_num = rte_eth_tx_burst(queue->ifp->port_id,
            queue->txq_id, queue->tx_pkts_burst, NET_IF_DPDK_QUEUE_MAX_TX_PKT_BURST);
        if (unlikely(tx_num != NET_IF_DPDK_QUEUE_MAX_TX_PKT_BURST)) {
            for (i = 0, j = tx_num; j < NET_IF_DPDK_QUEUE_MAX_TX_PKT_BURST; i++, j++) {
                queue->tx_pkts_burst[i] = queue->tx_pkts_burst[j];
            }
            queue->tx_offset = NET_IF_DPDK_QUEUE_MAX_TX_PKT_BURST - tx_num;
        } else {
            queue->tx_offset = 0;
        }
    }

    return 0;
}

static int net_if_dpdk_queue_send_pkts(net_if_dpdk_queue_t *queue,
    const net_if_send_pkt_t *pkts, unsigned int pkt_num)
{
    int err;
    unsigned int i, j, n, tx_num, send_num, sent_num;
    struct rte_mbuf *mbufs[NET_IF_DPDK_QUEUE_MAX_TX_PKT_BURST];
    unsigned char *p;
    net_if_dpdk_net_if_t *ifp = queue->ifp;

#ifdef LUNE_DEBUG
    lune_assert(NULL == NET_IF_GET_CURR_TX_PBUF());
#endif

    if (unlikely(NET_IF_DPDK_QUEUE_MAX_TX_PKT_BURST == queue->tx_offset)) {
        /*
            no cached mbuf sent in burst buffer the last time, probably overloaded
            retry sending and vacate burst buffer
        */
        tx_num = rte_eth_tx_burst(ifp->port_id, queue->txq_id, queue->tx_pkts_burst, queue->tx_offset);
        if (unlikely(0 == tx_num)) {
            /* no cached mbuf sent again, just quit */
            return 0;
        }

        if (unlikely(queue->tx_offset > tx_num)) {
            /* not all cached mbuf sent, quit sending for now */
            for (i = 0, j = tx_num; j < queue->tx_offset; i++, j++) {
                queue->tx_pkts_burst[i] = queue->tx_pkts_burst[j];
            }
            queue->tx_offset = queue->tx_offset - tx_num;

            return 0;
        }

        /* all cached mbuf sent, continue */
    }

    i = 0;
    sent_num = 0;
    send_num = pkt_num;

SEND_PKTS:
    if (send_num > (unsigned int)(NET_IF_DPDK_QUEUE_MAX_TX_PKT_BURST - queue->tx_offset)) {
        n = (unsigned int)(NET_IF_DPDK_QUEUE_MAX_TX_PKT_BURST - queue->tx_offset);
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

        queue->tx_pkts_burst[queue->tx_offset++] = mbufs[j];

        NET_IF_DPDK_CAP_PKT_OUT(ifp, pkts[i].buf, pkts[i].len);
    }

    sent_num += n;

    tx_num = rte_eth_tx_burst(ifp->port_id, queue->txq_id, queue->tx_pkts_burst, queue->tx_offset);
    if (unlikely(queue->tx_offset > tx_num)) {
        for (i = 0, j = tx_num; j < queue->tx_offset; i++, j++) {
            queue->tx_pkts_burst[i] = queue->tx_pkts_burst[j];
        }
        queue->tx_offset = queue->tx_offset - tx_num;

        return sent_num;
    }

    queue->tx_offset = 0;
    send_num -= tx_num;
    if (send_num > 0) {
        i = sent_num;
        goto SEND_PKTS;
    }

    return sent_num;
}

/*
    apply to LUNE_NET_IF_DPDK_QUEUE_CHAN only
*/
static inline int net_if_dpdk_queue_recv_broadcast(net_if_dpdk_queue_t *queue,
    struct rte_mbuf *mbuf)
{
    net_if_dpdk_net_if_t *ifp = queue->ifp;
    unsigned int i, j;
    int err, last_err = 0;
    net_if_dpdk_queue_t *q;

    for (i = 0; i < ifp->rxq_num; i++) {
        q = (net_if_dpdk_queue_t *)ifp->queue_array[i];
#ifdef LUNE_DEBUG
        lune_assert(q->chan_num > 0);
#endif
        for (j = 0; j < q->chan_num; j++) {
            if (0 != (err = net_if_dpdk_queue_chan_recv_from_queue(q->qifp,
                mbuf, j, queue->rxq_id))) {
                last_err = err;
            }
        }
    }

    return last_err;
}

/*
    apply to LUNE_NET_IF_DPDK_QUEUE_CHAN only
*/
static inline int net_if_dpdk_queue_recv_unicast(net_if_dpdk_queue_t *queue,
    net_if_dpdk_queue_t *dst_queue, struct rte_mbuf *mbuf, unsigned int chan_idx)
{
    return net_if_dpdk_queue_chan_recv_from_queue(dst_queue->qifp,
        mbuf, chan_idx, queue->rxq_id);
}

static inline int net_if_dpdk_queue_ip_get_pkt_to_dst_chan_idx(net_if_dpdk_queue_t *queue,
    struct rte_mbuf *mbuf, lune_net_if_aggr_type_en aggr_type)
{
    net_if_t *qifp = queue->qifp;
    net_if_dpdk_net_if_t *ifp = queue->ifp;
    aggr_net_if_t *ai = NET_IF_GET_AGGR_NET_IF(qifp);
    unsigned int idx;
    const lune_eth_hdr_t *ethh =
        (const lune_eth_hdr_t *)rte_pktmbuf_mtod(mbuf, unsigned char *);
    const lune_vlan_field_t *vf1, *vf2;
    unsigned short type, hdr_len;

    type = ethh->type;
    hdr_len = LUNE_ETH_HDR_LEN;

TYPE_PARSING:
    switch (type) {
    case ETH_TYPE_VLAN_N:
        vf1 = (const lune_vlan_field_t *)&ethh->type;
        type = *(const unsigned short *)vf1->data;
        hdr_len += LUNE_VLAN_FIELD_LEN;
        if (ETH_TYPE_VLAN_N == type) {
            vf2 = (const lune_vlan_field_t *)vf1->data;
            type = *(const unsigned short *)vf2->data;
            hdr_len += LUNE_VLAN_FIELD_LEN;
            if (unlikely(ETH_TYPE_VLAN_N == type)) {
                /* drop suspicious packet and log it */
                lune_log(LUNE_DBG,
                    "received suspicious packet on %s: type %4x in QinQ", queue->name, type);
                return ERR_SET_ERR(LUNE_ERR_NOT_SUPPORTED);
            }
        }

        goto TYPE_PARSING;
    case ETH_TYPE_ARP_N:
        /* broadcast */
        break;
    case ETH_TYPE_IPV4_N:
    {
        const lune_ipv4_hdr_t *ipv4h =
            (const lune_ipv4_hdr_t *)((const unsigned char *)ethh + hdr_len);

        if (IPV4_IS_BROADCAST_IP(ipv4h->dst_addr)) {
            /* broadcast */
            break;
        }

        if (LUNE_NET_IF_AGGR_IP_CLIENT == aggr_type) {
            idx = (unsigned int)(((lune_ntohl(ipv4h->dst_addr) - AGGR_NET_IF_IP_GET_START_IPV4(ai))
                / AGGR_NET_IF_IP_GET_STEP(ai)) % ifp->txq_num);
        } else {
            /* LUNE_NET_IF_AGGR_IP_SERVER */
            idx = (unsigned int)(((lune_ntohl(ipv4h->src_addr) - AGGR_NET_IF_IP_GET_START_IPV4(ai))
                / AGGR_NET_IF_IP_GET_STEP(ai)) % ifp->txq_num);
        }

        return idx;
    }
    case ETH_TYPE_IPV6_N:
    {
        const lune_ipv6_hdr_t *ipv6h =
            (const lune_ipv6_hdr_t *)((const unsigned char *)ethh + hdr_len);
        lune_ipv6_addr_t *addr = &AGGR_NET_IF_IP_GET_START_IPV6(ai);

        if (LUNE_NET_IF_AGGR_IP_CLIENT == aggr_type) {
            idx = (unsigned int)(((lune_ntohl(ipv6h->dst_addr.addr[3]) - addr->addr[3])
                / AGGR_NET_IF_IP_GET_STEP(ai)) % ifp->txq_num);
        } else {
            /* LUNE_NET_IF_AGGR_IP_SERVER */
            idx = (unsigned int)(((lune_ntohl(ipv6h->src_addr.addr[3]) - addr->addr[3])
                / AGGR_NET_IF_IP_GET_STEP(ai)) % ifp->txq_num);
        }

        return idx;
    }
    default:
        /* drop suspicious packet and log it */
        lune_log(LUNE_DBG,
            "received suspicious packet on %s: type %4x", queue->name, type);
        return ERR_SET_ERR(LUNE_ERR_NOT_SUPPORTED);
    }

    /* broadcast the packet to all channels */
    return ifp->txq_num;
}

static inline int net_if_dpdk_queue_mac_get_pkt_to_dst_chan_idx(net_if_dpdk_queue_t *queue,
    struct rte_mbuf *mbuf, lune_net_if_aggr_type_en aggr_type)
{
    net_if_t *qifp = queue->qifp;
    net_if_dpdk_net_if_t *ifp = queue->ifp;
    aggr_net_if_t *ai = NET_IF_GET_AGGR_NET_IF(qifp);
    unsigned int idx;
    const lune_eth_hdr_t *ethh =
        (const lune_eth_hdr_t *)rte_pktmbuf_mtod(mbuf, unsigned char *);
    const lune_vlan_field_t *vf1, *vf2;
    unsigned short type, hdr_len;
    unsigned long long mac;

    type = ethh->type;
    hdr_len = LUNE_ETH_HDR_LEN;

TYPE_PARSING:
    switch (type) {
    case ETH_TYPE_VLAN_N:
        vf1 = (const lune_vlan_field_t *)&ethh->type;
        type = *(const unsigned short *)vf1->data;
        hdr_len += LUNE_VLAN_FIELD_LEN;
        if (ETH_TYPE_VLAN_N == type) {
            vf2 = (const lune_vlan_field_t *)vf1->data;
            type = *(const unsigned short *)vf2->data;
            hdr_len += LUNE_VLAN_FIELD_LEN;
            if (unlikely(ETH_TYPE_VLAN_N == type)) {
                /* drop suspicious packet and log it */
                lune_log(LUNE_DBG,
                    "received suspicious packet on %s: type %4x in QinQ", queue->name, type);
                return ERR_SET_ERR(LUNE_ERR_NOT_SUPPORTED);
            }
        }

        goto TYPE_PARSING;
    case ETH_TYPE_ARP_N:
        /* broadcast */
        break;
    default:
        LUNE_MAC_TO_LL(ethh->dst_mac, mac);
        if (LUNE_BROADCAST_MAC_LL == mac) {
            /* broadcast */
            break;
        }

        if (LUNE_NET_IF_AGGR_MAC_SERVER == aggr_type) {
            LUNE_MAC_TO_LL(ethh->src_mac, mac);
        }

        idx = (unsigned int)(((mac - AGGR_NET_IF_MAC_GET_START_MAC(ai))
            / AGGR_NET_IF_MAC_GET_STEP(ai)) % ifp->txq_num);
        return idx;
    }

    /* broadcast the packet to all channels */
    return ifp->txq_num;
}

static inline int net_if_dpdk_queue_cust_get_pkt_to_dst_chan_idx(net_if_dpdk_queue_t *queue,
    struct rte_mbuf *mbuf)
{
    net_if_t *qifp = queue->qifp;
    net_if_dpdk_net_if_t *ifp = queue->ifp;
    aggr_net_if_t *ai = NET_IF_GET_AGGR_NET_IF(qifp);
    unsigned int idx;
    lune_net_if_aggr_recv_dist_func_t dist_func = AGGR_NET_IF_CUST_GET_DIST_FUNC(ai);

    idx = dist_func(AGGR_NET_IF_CUST_GET_DIST_DATA(ai),
        (const unsigned char *)rte_pktmbuf_mtod(mbuf, unsigned char *),
        rte_pktmbuf_data_len(mbuf));

    if (idx <= ifp->txq_num) {
        return idx;
    }

    /* idx > ifp->txq_num, drop the packet and log error */
    lune_log(LUNE_INFO, "invalid distribution index on %s: %d", queue->name, idx);
    return ERR_SET_ERR(LUNE_ERR_NET_IF_INTERNAL);
}

/*
    On success, return destination channel index if unicast, or number of queues if broadcast
    On failure, return errno
*/
static inline int net_if_dpdk_queue_get_pkt_to_dst_chan_idx(net_if_dpdk_queue_t *queue,
    struct rte_mbuf *mbuf)
{
    lune_net_if_aggr_type_en type =
        AGGR_NET_IF_GET_TYPE(NET_IF_GET_AGGR_NET_IF(queue->qifp));

    switch (type) {
    case LUNE_NET_IF_AGGR_IP_CLIENT:
    case LUNE_NET_IF_AGGR_IP_SERVER:
        return net_if_dpdk_queue_ip_get_pkt_to_dst_chan_idx(queue, mbuf, type);
    case LUNE_NET_IF_AGGR_MAC_CLIENT:
    case LUNE_NET_IF_AGGR_MAC_SERVER:
        return net_if_dpdk_queue_mac_get_pkt_to_dst_chan_idx(queue, mbuf, type);
    case LUNE_NET_IF_AGGR_CUSTOM:
        return net_if_dpdk_queue_cust_get_pkt_to_dst_chan_idx(queue, mbuf);
    default:
        lune_assert(0);
        return ERR_SET_ERR(LUNE_ERR_NET_IF_INTERNAL);
    }
}

static inline int net_if_dpdk_queue_distribute_pkt_to_chan(net_if_dpdk_queue_t *queue,
    struct rte_mbuf *mbuf, unsigned int idx)
{
    int err;
    net_if_dpdk_net_if_t *ifp = queue->ifp;
    net_if_t *qifp = queue->qifp;

    if (idx < ifp->txq_num) {
        /* unicast: send to specific channel */
        AGGR_SET_CURR_AGGR_NET_IF(qifp);
        err = net_if_dpdk_queue_recv_unicast(queue,
            (net_if_dpdk_queue_t *)ifp->queue_array[idx % ifp->rxq_num], mbuf, idx / ifp->rxq_num);
        AGGR_CLEAR_CURR_AGGR_NET_IF();
        return err;
    }

    /* broadcast: send to all channels (idx == ifp->txq_num) */
    AGGR_SET_CURR_AGGR_NET_IF(qifp);
    err = net_if_dpdk_queue_recv_broadcast(queue, mbuf);
    AGGR_CLEAR_CURR_AGGR_NET_IF();
    return err;
}

/*
    On success, return destination queue index if unicast, or number of queues if broadcast
    On failure, return errno
*/
static inline int net_if_dpdk_queue_get_pkt_to_dst_queue_idx(net_if_dpdk_queue_t *queue,
    struct rte_mbuf *mbuf)
{
    lune_eth_hdr_t *ethh = (lune_eth_hdr_t *)rte_pktmbuf_mtod(mbuf, unsigned char *);
    lune_vlan_field_t *vf1, *vf2;
    unsigned short type, hdr_len;
    net_if_dpdk_net_if_t *ifp = queue->ifp;
    unsigned int idx;

    type = ethh->type;
    hdr_len = LUNE_ETH_HDR_LEN;

TYPE_PARSING:
    switch (type) {
    case ETH_TYPE_VLAN_N:
        vf1 = (lune_vlan_field_t *)&ethh->type;
        type = *(unsigned short *)vf1->data;
        hdr_len += LUNE_VLAN_FIELD_LEN;
        if (ETH_TYPE_VLAN_N == type) {
            vf2 = (lune_vlan_field_t *)vf1->data;
            type = *(unsigned short *)vf2->data;
            hdr_len += LUNE_VLAN_FIELD_LEN;
        }
        if (unlikely(ETH_TYPE_VLAN_N == type)) {
            /* drop suspicious packet and log it */
            lune_log(LUNE_DBG,
                "received suspicious packet on %s: type %4x in QinQ", queue->name, type);
            return ERR_SET_ERR(LUNE_ERR_NOT_SUPPORTED);
        }
        goto TYPE_PARSING;
    case ETH_TYPE_ARP_N:
        /* broadcast */
        break;
    case ETH_TYPE_IPV4_N:
    {
        const lune_ipv4_hdr_t *ipv4h =
            (const lune_ipv4_hdr_t *)((const unsigned char *)ethh + hdr_len);

        if (IPV4_IS_BROADCAST_IP(ipv4h->dst_addr)) {
            /* broadcast */
            break;
        }

        if (LUNE_NET_IF_DPDK_RSS_TYPE_L3_DST == ifp->rss_type) {
            idx = (unsigned int)(((const unsigned char *)&ipv4h->dst_addr)[3] % ifp->rxq_num);
        } else {
            idx = (unsigned int)(((const unsigned char *)&ipv4h->src_addr)[3] % ifp->rxq_num);
        }

        return idx;
    }
    case ETH_TYPE_IPV6_N:
    {
        const lune_ipv6_hdr_t *ipv6h =
            (const lune_ipv6_hdr_t *)((const unsigned char *)ethh + hdr_len);

        if (LUNE_NET_IF_DPDK_RSS_TYPE_L3_DST == ifp->rss_type) {
            idx = (unsigned int)(lune_ntohl(ipv6h->dst_addr.addr[3]) % ifp->rxq_num);
        } else {
            idx = (unsigned int)(lune_ntohl(ipv6h->src_addr.addr[3]) % ifp->rxq_num);
        }

        return idx;
    }
    default:
        /* drop suspicious packet and log it */
        lune_log(LUNE_DBG,
            "received suspicious packet on %s: type %4x", queue->name, type);
        return ERR_SET_ERR(LUNE_ERR_NOT_SUPPORTED);
    }


    /* broadcast the packet to all queues */
    return ifp->rxq_num;
}

static inline int net_if_dpdk_queue_distribute_pkt_to_queue(net_if_dpdk_queue_t *queue,
    struct rte_mbuf *mbuf, unsigned int idx)
{
    unsigned int i;
    net_if_dpdk_net_if_t *ifp = queue->ifp;
    unsigned char *w_buf;
    net_if_dpdk_queue_t *sib_queue;

#ifdef LUNE_DEBUG
    lune_assert(ifp->txq_num == ifp->rxq_num);
#endif

    if (ifp->rxq_num == idx) {
        /* broadcast */
        for (i = 0; i < ifp->rxq_num; i++) {
            if (i == queue->rxq_id) {
                continue;
            }

            sib_queue = ifp->queue_array[i];
            if (NULL == (w_buf = ringbuf_get_write_frm(
                sib_queue->rx_rb_array[queue->rxq_id], NET_IF_DPDK_QUEUE_SIB_RX_RB_PKT_SIZE))) {
                lune_log(LUNE_INFO, "failed to distribute packet to %s", sib_queue->name);
                continue;
            }

            net_if_dpdk_mbuf_hold(mbuf);
            ((net_if_dpdk_queue_sib_rx_rb_hdr_t *)w_buf)->type = NET_IF_DPDK_QUEUE_SIB_RX_RB_TYPE_PTR;
            ((net_if_dpdk_queue_sib_rx_rb_hdr_t *)w_buf)->len = sizeof(struct rte_mbuf *);
            *(struct rte_mbuf **)((net_if_dpdk_queue_sib_rx_rb_hdr_t *)w_buf)->val = mbuf;
            ringbuf_write_frm_done(sib_queue->rx_rb_array[queue->rxq_id], w_buf);
        }

        return 1;
    }

    /* unicast */

    if (queue->rxq_id == idx) {
        /* local queue */
        return 1;
    }

    /* sibling queue */
    sib_queue = ifp->queue_array[idx];
    if (NULL == (w_buf = ringbuf_get_write_frm(sib_queue->rx_rb_array[queue->rxq_id],
        NET_IF_DPDK_QUEUE_SIB_RX_RB_PKT_SIZE))) {
        lune_log(LUNE_INFO, "failed to distribute packet to %s", sib_queue->name);
        return 1;
    }

    net_if_dpdk_mbuf_hold(mbuf);
    ((net_if_dpdk_queue_sib_rx_rb_hdr_t *)w_buf)->type = NET_IF_DPDK_QUEUE_SIB_RX_RB_TYPE_PTR;
    ((net_if_dpdk_queue_sib_rx_rb_hdr_t *)w_buf)->len = sizeof(struct rte_mbuf *);
    *(struct rte_mbuf **)((net_if_dpdk_queue_sib_rx_rb_hdr_t *)w_buf)->val = mbuf;
    ringbuf_write_frm_done(sib_queue->rx_rb_array[queue->rxq_id], w_buf);
    return 0;
}

static int net_if_dpdk_queue_recv_pkts(net_if_dpdk_queue_t *queue)
{
    int err, last_err = 0, idx;
    unsigned int i, j, attempts, frm_cnt, is_ready;
    struct rte_mbuf *mbuf;
    unsigned short rx_num;
    net_if_dpdk_net_if_t *ifp = queue->ifp;
    ringbuf_frm_t frms_burst[NET_IF_DPDK_QUEUE_MAX_RX_RB_FRM_BURST];

    if (NET_IF_IS_AGGR(queue->ifp)) {
        is_ready = aggr_is_net_if_ready(NET_IF_GET_AGGR_NET_IF(queue->qifp));
    } else {
        is_ready = 1;
    }

    attempts = 0;
    while (attempts++ < NET_IF_DPDK_QUEUE_MAX_RECV_PKTS_ATTEMPTS) {
        if (!NET_IF_DPDK_QUEUE_IS_DPDK_QUEUE_CHAN(queue)
            && NET_IF_DPDK_IS_DISTRIB_SET(queue->ifp)) {
            for (i = 0; i < ifp->rxq_num; i++) {
                if (i == queue->rxq_id) {
                    continue;
                }

                if (0 != (frm_cnt = ringbuf_get_read_frm_burst(queue->rx_rb_array[i],
                    frms_burst, NET_IF_DPDK_QUEUE_MAX_RX_RB_FRM_BURST))) {
                    for (j = 0; j < frm_cnt; j++) {
#ifdef LUNE_DEBUG
                        queue->prof_dist_pkt_in++;
#endif
                        switch (((net_if_dpdk_queue_sib_rx_rb_hdr_t *)(frms_burst[j].buf))->type) {
                        case NET_IF_DPDK_QUEUE_SIB_RX_RB_TYPE_PTR:
                        {
                            struct rte_mbuf *mbuf;
                            mbuf = *(struct rte_mbuf **)
                                ((net_if_dpdk_queue_sib_rx_rb_hdr_t *)(frms_burst[j].buf))->val;
                            NET_IF_DPDK_QUEUE_SET_SIB_RX_RB_PKT(queue);
                            queue->sib_rx_rb_hdr =
                                (net_if_dpdk_queue_sib_rx_rb_hdr_t *)frms_burst[j].buf;
                            queue->sib_rx_rb_idx = i;
                            err = net_if_process_single_net_if_recv_func(queue->qifp,
                                rte_pktmbuf_mtod(mbuf, unsigned char *),
                                rte_pktmbuf_data_len(mbuf), 1);
                            if (unlikely(0 != err)) {
                                last_err = err;
                            }

                            if (NET_IF_DPDK_QUEUE_IS_SIB_RX_RB_PKT(queue)) {
                                /* recv_fwd_pkt */
                                ringbuf_read_frm_done(queue->rx_rb_array[i],
                                    (unsigned char *)frms_burst[j].buf);
                                net_if_dpdk_mbuf_put(mbuf);
                                NET_IF_DPDK_QUEUE_CLEAR_SIB_RX_RB_PKT(queue);
                                queue->sib_rx_rb_hdr = NULL;
                                queue->sib_rx_rb_idx = ifp->rxq_num;
                            } else {
                                /* recv_done */
                            }

                            break;
                        }
                        default:
                            lune_assert(0);
                            ringbuf_read_frm_done(queue->rx_rb_array[i],
                                (unsigned char *)frms_burst[j].buf);
                            return -LUNE_ERR_NET_IF_INTERNAL;
                        }
                    }
                }
            }
        }

        rx_num = rte_eth_rx_burst(ifp->port_id,
            queue->rxq_id, queue->rx_pkts_burst, NET_IF_DPDK_QUEUE_MAX_RX_PKT_BURST);
        if (0 == rx_num) {
            continue;
        }

        queue->rx_offset = 0;
        for (i = 0; i < rx_num; i++) {
            mbuf = queue->rx_pkts_burst[i];

            err = 0;
            if (unlikely((mbuf->ol_flags & PKT_RX_IP_CKSUM_MASK) == PKT_RX_IP_CKSUM_BAD)) {
                queue->pkt_in_ipv4_csum_err++;
                err = 1;
            }
            if (unlikely((mbuf->ol_flags & PKT_RX_L4_CKSUM_MASK) == PKT_RX_L4_CKSUM_BAD)) {
                queue->pkt_in_l4_csum_err++;
                err = 1;
            }

            net_if_dpdk_mbuf_init_and_hold(mbuf);

            NET_IF_CAP_PKT(queue->qifp,
                rte_pktmbuf_mtod(mbuf, unsigned char *), rte_pktmbuf_data_len(mbuf));
            NET_IF_DPDK_CAP_MBUF_IN(queue->ifp, mbuf);

            if (unlikely(err)) {
                /* drop packet with checksum error */
#ifdef LUNE_DEBUG
                queue->prof_local_pkt_dropped++;
#endif
                net_if_dpdk_mbuf_put(mbuf);
                queue->rx_offset++;
                continue;
            }

            if (unlikely(!is_ready)) {
                /* not all channel interfaces are up and running, drop it */
#ifdef LUNE_DEBUG
                queue->prof_local_pkt_dropped++;
#endif
                net_if_dpdk_mbuf_put(mbuf);
                queue->rx_offset++;
                continue;
            }

            if (NET_IF_DPDK_QUEUE_IS_DPDK_QUEUE_CHAN(queue)) {
                if (unlikely(0 > (idx = net_if_dpdk_queue_get_pkt_to_dst_chan_idx(queue, mbuf)))) {
                    /* failed to get destination channel, drop it */
#ifdef LUNE_DEBUG
                    queue->prof_local_pkt_dropped++;
#endif
                    net_if_dpdk_mbuf_put(mbuf);
                    queue->rx_offset++;
                    continue;
                }

                err = net_if_dpdk_queue_distribute_pkt_to_chan(queue, mbuf, idx);
                goto RECV_DONE;
            }

            if (NET_IF_DPDK_IS_DISTRIB_SET(queue->ifp)) {
                if (unlikely(0 > (idx = net_if_dpdk_queue_get_pkt_to_dst_queue_idx(queue, mbuf)))) {
                    /* failed to get destination queue, drop it */
#ifdef LUNE_DEBUG
                    queue->prof_local_pkt_dropped++;
#endif
                    net_if_dpdk_mbuf_put(mbuf);
                    queue->rx_offset++;
                    continue;
                }

                if (!net_if_dpdk_queue_distribute_pkt_to_queue(queue, mbuf, idx)) {
#ifdef LUNE_DEBUG
                    queue->prof_dist_pkt_out++;
#endif
                    net_if_dpdk_mbuf_put(mbuf);
                    queue->rx_offset++;
                    continue;
                }
            }

#ifdef LUNE_DEBUG
            queue->prof_local_pkt_in++;
#endif

            err = net_if_process_single_net_if_recv_func(queue->qifp,
                rte_pktmbuf_mtod(mbuf, unsigned char *), rte_pktmbuf_data_len(mbuf), 1);

RECV_DONE:
            if (unlikely(0 != err)) {
                last_err = err;
            }

            if (i == queue->rx_offset) {
                /* recv_fwd_pkt once */
                net_if_dpdk_mbuf_put(mbuf);
                queue->rx_offset++;
            } else {
                /*
                    recv_done once, or
                    multiple recv_fwd_pkt and recv_done once
                */
#ifdef LUNE_DEBUG
                lune_assert((i + 1) == queue->rx_offset);
#endif
            }
        }
    }

    return last_err;
}

static void net_if_dpdk_queue_recv_done(net_if_dpdk_queue_t *queue)
{
    if (NET_IF_DPDK_QUEUE_IS_SIB_RX_RB_PKT(queue)) {
        net_if_dpdk_queue_sib_rx_rb_hdr_t *hdr = queue->sib_rx_rb_hdr;
        switch (hdr->type) {
        case NET_IF_DPDK_QUEUE_SIB_RX_RB_TYPE_PTR:
            net_if_dpdk_mbuf_put(*(struct rte_mbuf **)hdr->val);
            break;
        default:
            lune_assert(0);
            ringbuf_read_frm_done(queue->rx_rb_array[queue->sib_rx_rb_idx],
                (unsigned char *)hdr);
            return;
        }
        ringbuf_read_frm_done(queue->rx_rb_array[queue->sib_rx_rb_idx],
            (unsigned char *)hdr);
        NET_IF_DPDK_QUEUE_CLEAR_SIB_RX_RB_PKT(queue);
        queue->sib_rx_rb_hdr = NULL;
        queue->sib_rx_rb_idx = queue->ifp->rxq_num;
    } else {
        net_if_dpdk_mbuf_put(queue->rx_pkts_burst[queue->rx_offset++]);
    }
}

static void net_if_dpdk_queue_recv_fwd_pkt(net_if_dpdk_queue_t *queue, void **pdata)
{
    if (NET_IF_DPDK_QUEUE_IS_SIB_RX_RB_PKT(queue)) {
        net_if_dpdk_queue_sib_rx_rb_hdr_t *hdr = queue->sib_rx_rb_hdr;
        *pdata = *(struct rte_mbuf **)hdr->val;
    } else {
        *pdata = queue->rx_pkts_burst[queue->rx_offset];
    }
    net_if_dpdk_mbuf_hold(*pdata);
}

static void net_if_dpdk_queue_recv_free_pkt(net_if_dpdk_queue_t *queue __attribute__((unused)),
    unsigned char *buf __attribute__((unused)), void *data)
{
    net_if_dpdk_mbuf_put(data);
}

static int net_if_dpdk_queue_get_opt(net_if_dpdk_queue_t *queue,
    net_if_opt_en opt, unsigned char *opt_val, unsigned int opt_len)
{
    lune_assert(NULL != opt_val);

    switch (opt) {
    case NET_IF_OPT_GET_HW_CSUM:
    {
        unsigned short csum_offloads;

        if (opt_len != sizeof(unsigned short)) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        csum_offloads = 0;
        if (queue->ifp->port_conf.rxmode.offloads & DEV_RX_OFFLOAD_IPV4_CKSUM) {
            NET_IF_OPT_SET_HW_RX_CSUM_IPV4(csum_offloads);
        }
        if (queue->ifp->port_conf.rxmode.offloads & DEV_RX_OFFLOAD_TCP_CKSUM) {
            NET_IF_OPT_SET_HW_RX_CSUM_TCP(csum_offloads);
        }
        if (queue->ifp->port_conf.rxmode.offloads & DEV_RX_OFFLOAD_UDP_CKSUM) {
            NET_IF_OPT_SET_HW_RX_CSUM_UDP(csum_offloads);
        }
        if (queue->ifp->port_conf.txmode.offloads & DEV_TX_OFFLOAD_IPV4_CKSUM) {
            NET_IF_OPT_SET_HW_TX_CSUM_IPV4(csum_offloads);
        }
        if (queue->ifp->port_conf.txmode.offloads & DEV_TX_OFFLOAD_TCP_CKSUM) {
            NET_IF_OPT_SET_HW_TX_CSUM_TCP(csum_offloads);
        }
        if (queue->ifp->port_conf.txmode.offloads & DEV_TX_OFFLOAD_UDP_CKSUM) {
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

        *(unsigned short *)opt_val = queue->ifp->mtu;
        break;
    case NET_IF_OPT_GET_STATS:
    {
        lune_net_if_stats_t *pstats;
        struct rte_eth_stats stats;

        if (opt_len != sizeof(lune_net_if_stats_t)) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        pstats = (lune_net_if_stats_t *)opt_val;

        if (0 != (rte_eth_stats_get(queue->ifp->port_id, &stats))) {
            lune_log(LUNE_INFO, "failed to get statistics of %s", queue->ifp->name);
            return ERR_SET_ERR(LUNE_ERR_NET_IF_INTERNAL);
        }

        pstats->pkt_in = stats.ipackets;
        pstats->pkt_out = stats.opackets;
        pstats->pkt_in_dropped = stats.ierrors;
        pstats->pkt_out_dropped = stats.oerrors;
        pstats->pkt_in_ipv4_csum_err = queue->pkt_in_ipv4_csum_err;
        pstats->pkt_in_l4_csum_err = queue->pkt_in_l4_csum_err;
        pstats->byte_in = stats.ibytes;
        pstats->byte_out = stats.obytes;

        break;
    }
    case NET_IF_OPT_GET_PORT_ID:
        if (opt_len != sizeof(unsigned short)) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        *(unsigned short *)opt_val = queue->ifp->port_id;
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

static int net_if_dpdk_queue_set_opt(net_if_dpdk_queue_t *queue,
    net_if_opt_en opt,
    const unsigned char *opt_val,
    unsigned int opt_len __attribute__((unused)))
{
    int err;
    net_if_dpdk_net_if_t *ifp = queue->ifp;

    switch (opt) {
    case NET_IF_OPT_SET_MTU:
        /* TODO: set mtu to dpdk driver */
        ifp->mtu = *(const unsigned short *)opt_val;
        break;
    case NET_IF_OPT_PCAP_START:
        pthread_spin_lock(&ifp->lock);
        if (NET_IF_DPDK_IS_CAP_ENABLED(ifp)) {
            pthread_spin_unlock(&ifp->lock);
            return ERR_SET_ERR(LUNE_ERR_ALREADY_STARTED);
        }

        if (NULL == (ifp->net_if_dpdk_cap = net_if_dpdk_cap_start(ifp->name,
            ((const lune_net_if_pcap_t *)opt_val)->file_name))) {
            pthread_spin_unlock(&ifp->lock);
            return ERR_GET_LAST_ERR();
        }
        pthread_spin_unlock(&ifp->lock);
        return 0;
    case NET_IF_OPT_PCAP_STOP:
        pthread_spin_lock(&ifp->lock);
        if (!NET_IF_DPDK_IS_CAP_ENABLED(ifp)) {
            pthread_spin_unlock(&ifp->lock);
            return ERR_SET_ERR(LUNE_ERR_NOT_STARTED);
        }

        net_if_dpdk_cap_stop(ifp->net_if_dpdk_cap);
        ifp->net_if_dpdk_cap = NULL;
        pthread_spin_unlock(&ifp->lock);
        return 0;
    case NET_IF_OPT_DISABLE_HW_CSUM:
        pthread_spin_lock(&ifp->lock);
        ifp->port_conf.rxmode.offloads &=
            ~(DEV_RX_OFFLOAD_IPV4_CKSUM | DEV_RX_OFFLOAD_TCP_CKSUM | DEV_RX_OFFLOAD_UDP_CKSUM);
        ifp->port_conf.txmode.offloads &=
            ~(DEV_TX_OFFLOAD_IPV4_CKSUM | DEV_TX_OFFLOAD_TCP_CKSUM | DEV_TX_OFFLOAD_UDP_CKSUM);

        if (0 != (err = rte_eth_dev_configure(ifp->port_id,
            ifp->rxq_num, ifp->txq_num, &ifp->port_conf))) {
            lune_log(LUNE_WARN, "failed to configure %s: %d", ifp->name, rte_strerror(-err));
            pthread_spin_unlock(&ifp->lock);
            return ERR_SET_ERR(LUNE_ERR_SYS_ERR);
        }
        pthread_spin_unlock(&ifp->lock);
        break;
    case NET_IF_OPT_DPDK_QUEUE_SET_DISTRIB:
        pthread_spin_lock(&ifp->lock);
        if (NET_IF_DPDK_IS_STARTED(ifp)) {
            pthread_spin_unlock(&ifp->lock);
            return ERR_SET_ERR(LUNE_ERR_NET_IF_ACTIVE);
        }

        if (NET_IF_DPDK_IS_DISTRIB_SET(ifp)) {
            pthread_spin_unlock(&ifp->lock);
            lune_log(LUNE_INFO, "packet distribution set via %s: already set on %s",
                queue->name, ifp->name);
            break;
        }

        NET_IF_DPDK_SET_DISTRIB(ifp);
        pthread_spin_unlock(&ifp->lock);
        break;
    case NET_IF_OPT_DPDK_QUEUE_CLEAR_DISTRIB:
        pthread_spin_lock(&ifp->lock);
        if (NET_IF_DPDK_IS_STARTED(ifp)) {
            pthread_spin_unlock(&ifp->lock);
            return ERR_SET_ERR(LUNE_ERR_NET_IF_ACTIVE);
        }

        if (!NET_IF_DPDK_IS_DISTRIB_SET(ifp)) {
            pthread_spin_unlock(&ifp->lock);
            lune_log(LUNE_INFO, "packet distribution cleared via %s: already cleared on %s",
                queue->name, ifp->name);
            break;
        }

        NET_IF_DPDK_CLEAR_DISTRIB(ifp);
        pthread_spin_unlock(&ifp->lock);
        break;
    default:
        return ERR_SET_ERR(LUNE_ERR_NOT_SUPPORTED);
    }

    return 0;
}

net_if_drv_t g_net_if_drv_dpdk_queue = {
    .type = LUNE_NET_IF_DPDK_QUEUE,
    .name = "dpdk queue",
    .add_net_if = (net_if_add_net_if_func_t)net_if_dpdk_queue_add_net_if,
    .del_net_if = (net_if_del_net_if_func_t)net_if_dpdk_queue_del_net_if,
    .is_up = (net_if_is_up_func_t)net_if_dpdk_queue_is_up,
    .set_up = (net_if_set_up_func_t)net_if_dpdk_queue_set_up,
    .set_down = (net_if_set_down_func_t)net_if_dpdk_queue_set_down,
    .send = (net_if_send_func_t)net_if_dpdk_queue_send,
    .send_pkts = (net_if_send_pkts_func_t)net_if_dpdk_queue_send_pkts,
    .recv = NULL,
    .recv_pkts = (net_if_recv_pkts_func_t)net_if_dpdk_queue_recv_pkts,
    .recv_done = (net_if_recv_done_func_t)net_if_dpdk_queue_recv_done,
    .recv_fwd_pkt = (net_if_recv_fwd_pkt_func_t)net_if_dpdk_queue_recv_fwd_pkt,
    .recv_free_pkt = (net_if_recv_free_pkt_func_t)net_if_dpdk_queue_recv_free_pkt,
    .get_opt = (net_if_get_opt_func_t)net_if_dpdk_queue_get_opt,
    .set_opt = (net_if_set_opt_func_t)net_if_dpdk_queue_set_opt,
};
