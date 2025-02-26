/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2024 Lune Reseau, Inc.
 */

#include "lune/arp.h"
#include "lune/atomic.h"
#include "lune/ipv4.h"
#include "lune/mac.h"
#include "lune/mem.h"
#include "lune/net.h"
#include "lune/os/linux.h"

#include "drv/aggr.h"
#ifdef LUNE_BUILD_DPDK
#include "drv/dpdk/net_if_dpdk.h"
#include "drv/dpdk/net_if_dpdk_queue.h"
#endif
#include "drv/net_if.h"
#include "drv/net_if_chan.h"
#include "kernel/sched.h"
#include "lib/htable.h"
#include "lib/msgqueue.h"
#include "log/log.h"
#include "net/mac.h"
#include "rt/core.h"
#include "utils/cap.h"

#define AGGR_NET_IF_HTABLE_SIZE_IN_BIT      (8)
#define AGGR_NET_IF_HTABLE_SIZE             (1 << (AGGR_NET_IF_HTABLE_SIZE_IN_BIT))
#define AGGR_NET_IF_HTABLE_MASK             (AGGR_NET_IF_HTABLE_SIZE - 1)

#define AGGR_CHAN_TX_MSGQUEUE_SIZE_IN_BIT   (23)
#define AGGR_CHAN_TX_MSGQUEUE_SIZE          (1 << AGGR_CHAN_TX_MSGQUEUE_SIZE_IN_BIT)

#pragma pack(8)
typedef struct _aggr_chan_tx_hdr {
#define AGGR_CHAN_TX_PKT                    (0)
#define AGGR_CHAN_TX_PBUF_PTR               (1)
#define AGGR_CHAN_TX_PBUF_PKT               (2)
    unsigned int type;
    unsigned int len;
    unsigned char val[0];
} aggr_chan_tx_hdr_t;

typedef struct _aggr_chan_tx_pbuf_pkt_hdr {
    unsigned long long pkt_info;
} aggr_chan_tx_pbuf_pkt_hdr_t;
#pragma pack()

__thread net_if_t *g_aggr_curr_ifp = NULL;
static void *s_aggr_net_if_htable = NULL;

static void aggr_net_if_hold(aggr_net_if_t *ai)
{
#ifdef LUNE_DEBUG
    lune_assert(lune_atomic32_get(&ai->ref_cnt) >= 0);
#endif
    lune_atomic32_inc(&ai->ref_cnt);
}

static void aggr_net_if_put(aggr_net_if_t *ai)
{
#ifdef LUNE_DEBUG
    lune_assert(lune_atomic32_get(&ai->ref_cnt) > 0);
#endif
    if (lune_atomic32_dec_is_zero(&ai->ref_cnt)) {
        lune_assert(!pthread_spin_destroy(&ai->lock));
        lune_free_mt(ai);
    }
}

static inline aggr_net_if_t *aggr_net_if_find(const char *name)
{
    aggr_net_if_t psd_ai;

    strcpy(psd_ai.name, name);
    return htable_find_mt((void *)&psd_ai, s_aggr_net_if_htable);
}

static inline void aggr_net_if_find_done(aggr_net_if_t *ai)
{
    lune_assert(!htable_find_done_mt((void *)ai, s_aggr_net_if_htable));
}

static inline int aggr_net_if_insert(aggr_net_if_t *ai)
{
    return htable_insert_mt((void *)ai, s_aggr_net_if_htable);
}

static inline int aggr_net_if_remove(aggr_net_if_t *ai)
{
    return htable_remove_mt((void *)ai, s_aggr_net_if_htable);
}

void aggr_net_if_update_tcp_stats(net_if_t *ifp)
{
    aggr_net_if_t *ai = ifp->aip;
    unsigned int i;

    if ((int)ai->total_chan_num != lune_atomic32_get(&ai->curr_active_chan_num)) {
        /* statistics only works when all channel interfaces are up and running */
        return;
    }

    memset(&ifp->tcp_stats, 0x00, sizeof(lune_net_if_tcp_stats_t));
    for (i = 0; i < ai->curr_chan_num; i++) {
        ifp->tcp_stats.total_att_conns += ai->chan_array[i]->ifp->tcp_stats.total_att_conns;
        ifp->tcp_stats.att_conn_rate += ai->chan_array[i]->ifp->tcp_stats.att_conn_rate;
        ifp->tcp_stats.total_est_conns += ai->chan_array[i]->ifp->tcp_stats.total_est_conns;
        ifp->tcp_stats.est_conn_rate += ai->chan_array[i]->ifp->tcp_stats.est_conn_rate;
        ifp->tcp_stats.total_close_conns += ai->chan_array[i]->ifp->tcp_stats.total_close_conns;
        ifp->tcp_stats.close_conn_rate += ai->chan_array[i]->ifp->tcp_stats.close_conn_rate;
        ifp->tcp_stats.total_fail_conns += ai->chan_array[i]->ifp->tcp_stats.total_fail_conns;
        ifp->tcp_stats.total_abrt_conns += ai->chan_array[i]->ifp->tcp_stats.total_abrt_conns;
        ifp->tcp_stats.concurrent_conns += ai->chan_array[i]->ifp->tcp_stats.concurrent_conns;

        ifp->tcp_stats.byte_in += ai->chan_array[i]->ifp->tcp_stats.byte_in;
        ifp->tcp_stats.byte_out += ai->chan_array[i]->ifp->tcp_stats.byte_out;
        ifp->tcp_stats.byte_in_rate += ai->chan_array[i]->ifp->tcp_stats.byte_in_rate;
        ifp->tcp_stats.byte_out_rate += ai->chan_array[i]->ifp->tcp_stats.byte_out_rate;

        ifp->tcp_stats.pkt_in += ai->chan_array[i]->ifp->tcp_stats.pkt_in;
        ifp->tcp_stats.pkt_out += ai->chan_array[i]->ifp->tcp_stats.pkt_out;
        ifp->tcp_stats.pkt_in_rate += ai->chan_array[i]->ifp->tcp_stats.pkt_in_rate;
        ifp->tcp_stats.pkt_out_rate += ai->chan_array[i]->ifp->tcp_stats.pkt_out_rate;

        ifp->tcp_stats.close_time_10ms += ai->chan_array[i]->ifp->tcp_stats.close_time_10ms;
        ifp->tcp_stats.close_time_100ms += ai->chan_array[i]->ifp->tcp_stats.close_time_100ms;
        ifp->tcp_stats.close_time_1000ms += ai->chan_array[i]->ifp->tcp_stats.close_time_1000ms;
        ifp->tcp_stats.close_time_10000ms += ai->chan_array[i]->ifp->tcp_stats.close_time_10000ms;
        ifp->tcp_stats.close_time_high += ai->chan_array[i]->ifp->tcp_stats.close_time_high;
        ifp->tcp_stats.close_time_total_num += ai->chan_array[i]->ifp->tcp_stats.close_time_total_num;
        ifp->tcp_close_time_total += ai->chan_array[i]->ifp->tcp_close_time_total;

        ifp->tcp_stats.resp_time_10ms += ai->chan_array[i]->ifp->tcp_stats.resp_time_10ms;
        ifp->tcp_stats.resp_time_100ms += ai->chan_array[i]->ifp->tcp_stats.resp_time_100ms;
        ifp->tcp_stats.resp_time_1000ms += ai->chan_array[i]->ifp->tcp_stats.resp_time_1000ms;
        ifp->tcp_stats.resp_time_10000ms += ai->chan_array[i]->ifp->tcp_stats.resp_time_10000ms;
        ifp->tcp_stats.resp_time_high += ai->chan_array[i]->ifp->tcp_stats.resp_time_high;
        ifp->tcp_stats.resp_time_total_num += ai->chan_array[i]->ifp->tcp_stats.resp_time_total_num;
        ifp->tcp_resp_time_total += ai->chan_array[i]->ifp->tcp_resp_time_total;

        ifp->tcp_stats.setup_time_10ms += ai->chan_array[i]->ifp->tcp_stats.setup_time_10ms;
        ifp->tcp_stats.setup_time_100ms += ai->chan_array[i]->ifp->tcp_stats.setup_time_100ms;
        ifp->tcp_stats.setup_time_1000ms += ai->chan_array[i]->ifp->tcp_stats.setup_time_1000ms;
        ifp->tcp_stats.setup_time_10000ms += ai->chan_array[i]->ifp->tcp_stats.setup_time_10000ms;
        ifp->tcp_stats.setup_time_high += ai->chan_array[i]->ifp->tcp_stats.setup_time_high;
        ifp->tcp_stats.setup_time_total_num += ai->chan_array[i]->ifp->tcp_stats.setup_time_total_num;
        ifp->tcp_setup_time_total += ai->chan_array[i]->ifp->tcp_setup_time_total;

        ifp->tcp_stats.session_duration_10ms += ai->chan_array[i]->ifp->tcp_stats.session_duration_10ms;
        ifp->tcp_stats.session_duration_100ms += ai->chan_array[i]->ifp->tcp_stats.session_duration_100ms;
        ifp->tcp_stats.session_duration_1000ms += ai->chan_array[i]->ifp->tcp_stats.session_duration_1000ms;
        ifp->tcp_stats.session_duration_10000ms += ai->chan_array[i]->ifp->tcp_stats.session_duration_10000ms;
        ifp->tcp_stats.session_duration_high += ai->chan_array[i]->ifp->tcp_stats.session_duration_high;
        ifp->tcp_stats.session_duration_total_num += ai->chan_array[i]->ifp->tcp_stats.session_duration_total_num;
        ifp->tcp_session_duration_total += ai->chan_array[i]->ifp->tcp_session_duration_total;

        /* ssl statistics */
        ifp->ssl_stats.total_att_conns += ai->chan_array[i]->ifp->ssl_stats.total_att_conns;
        ifp->ssl_stats.att_conn_rate += ai->chan_array[i]->ifp->ssl_stats.att_conn_rate;
        ifp->ssl_stats.total_est_conns += ai->chan_array[i]->ifp->ssl_stats.total_est_conns;
        ifp->ssl_stats.est_conn_rate += ai->chan_array[i]->ifp->ssl_stats.est_conn_rate;
        ifp->ssl_stats.total_close_conns += ai->chan_array[i]->ifp->ssl_stats.total_close_conns;
        ifp->ssl_stats.close_conn_rate += ai->chan_array[i]->ifp->ssl_stats.close_conn_rate;
        ifp->ssl_stats.total_fail_conns += ai->chan_array[i]->ifp->ssl_stats.total_fail_conns;
        ifp->ssl_stats.concurrent_conns += ai->chan_array[i]->ifp->ssl_stats.concurrent_conns;

        ifp->ssl_stats.byte_dec += ai->chan_array[i]->ifp->ssl_stats.byte_dec;
        ifp->ssl_stats.byte_enc += ai->chan_array[i]->ifp->ssl_stats.byte_enc;
        ifp->ssl_stats.byte_dec_rate += ai->chan_array[i]->ifp->ssl_stats.byte_dec_rate;
        ifp->ssl_stats.byte_enc_rate += ai->chan_array[i]->ifp->ssl_stats.byte_enc_rate;
    }

    if (ifp->tcp_stats.close_time_total_num > 0) {
        ifp->tcp_stats.avg_close_time_ms = (float)ifp->tcp_close_time_total
            / ifp->tcp_stats.close_time_total_num / LUNE_TIME_MILLISECOND;
    }
    if (ifp->tcp_stats.resp_time_total_num > 0) {
        ifp->tcp_stats.avg_resp_time_ms = (float)ifp->tcp_resp_time_total
            / ifp->tcp_stats.resp_time_total_num / LUNE_TIME_MILLISECOND;
    }
    if (ifp->tcp_stats.setup_time_total_num > 0) {
        ifp->tcp_stats.avg_setup_time_ms = (float)ifp->tcp_setup_time_total
            / ifp->tcp_stats.setup_time_total_num / LUNE_TIME_MILLISECOND;
    }
    if (ifp->tcp_stats.session_duration_total_num > 0) {
        ifp->tcp_stats.avg_session_duration_ms = (float)ifp->tcp_session_duration_total
            / ifp->tcp_stats.session_duration_total_num / LUNE_TIME_MILLISECOND;
    }
}

/*
    caller MUST guarantee aggr_add_net_if() and aggr_del_net_if() are
    paired within the same thread where net_if is added
*/
void *aggr_add_net_if(const char *name, const lune_net_if_aggr_conf_t *conf, net_if_t *ifp)
{
    unsigned int is_ref_cnt_avail = 0;
    aggr_net_if_t *ai;

    lune_assert(NULL != name);
    lune_assert(NULL != conf);
    lune_assert(NULL != ifp);

    if (conf->chan_num < AGGR_NET_IF_MIN_CHAN_PER_AGGR_NUM
        || conf->chan_num > AGGR_NET_IF_MAX_CHAN_PER_AGGR_NUM
        || conf->type < LUNE_NET_IF_AGGR_MAC_CLIENT
        || conf->type >= LUNE_NET_IF_AGGR_MAX) {
        ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        goto ERR_1;
    }

#ifdef LUNE_BUILD_DPDK
    if (LUNE_NET_IF_DPDK_QUEUE == ifp->type
        && !net_if_dpdk_queue_is_valid_chan_num(ifp->net_if_data, conf->chan_num)) {
        ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        goto ERR_1;
    }
#endif

    if (NULL != (ai = aggr_net_if_find(name))) {
        aggr_net_if_find_done(ai);
        ERR_SET_ERR(LUNE_ERR_ALREADY_EXIST);
        goto ERR_1;
    }

    if (NULL == (ai = lune_malloc_mt(sizeof(aggr_net_if_t)))) {
        goto ERR_1;
    }

    dlist_init_node(&ai->node);
    lune_atomic32_set(&ai->ref_cnt, 0);
    ai->tx_task_id = LUNE_INVALID_ID;
    switch (conf->type) {
    case LUNE_NET_IF_AGGR_IP_CLIENT:
    case LUNE_NET_IF_AGGR_IP_SERVER:
        if (0 == conf->ip.step) {
            ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
            goto ERR_2;
        }
        LUNE_IP_CPY(&ai->ip.start_ip, &conf->ip.start_ip);
        LUNE_IP_CPY(&ai->ip.end_ip, &conf->ip.end_ip);
        ai->ip.step = conf->ip.step;
        break;
    case LUNE_NET_IF_AGGR_MAC_CLIENT:
    case LUNE_NET_IF_AGGR_MAC_SERVER:
        if (0 == conf->mac.step) {
            ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
            goto ERR_2;
        }
        LUNE_MAC_TO_LL(conf->mac.start_mac, ai->mac.start_mac);
        LUNE_MAC_TO_LL(conf->mac.end_mac, ai->mac.end_mac);
        ai->mac.step = conf->mac.step;
        break;
    case LUNE_NET_IF_AGGR_CUSTOM:
        if (NULL == conf->cust.dist) {
            ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
            goto ERR_2;
        }
        ai->cust.dist = conf->cust.dist;
        ai->cust.data = conf->cust.data;
        break;
    default:
        ERR_SET_ERR(LUNE_ERR_NET_IF_INTERNAL);
        goto ERR_2;
    }

    ai->type = conf->type;
    ai->total_chan_num = conf->chan_num;
    ai->curr_chan_num = 0;
    lune_atomic32_set(&ai->curr_active_chan_num, 0);
    memset(ai->chan_array, 0x00, sizeof(aggr_chan_t *) * AGGR_NET_IF_MAX_CHAN_PER_AGGR_NUM);
    ai->ifp = ifp;
    strcpy(ai->name, name);
    if (0 != pthread_spin_init(&ai->lock, PTHREAD_PROCESS_PRIVATE)) {
        ERR_SET_ERR(LUNE_ERR_SYS_ERR);
        goto ERR_2;
    }

    ai->flags = 0;
    if (0 == (ifp->drv->get_opt(ifp->net_if_data,
        NET_IF_OPT_IS_RECV_REFCNT_AVAIL, (unsigned char *)&is_ref_cnt_avail, sizeof(is_ref_cnt_avail)))
        && is_ref_cnt_avail) {
        AGGR_NET_IF_SET_REFCNT_AVAIL(ai);
    }

    lune_atomic32_set(&ai->tx_pkt_cnt, 0);

    aggr_net_if_hold(ai);
    if (0 != aggr_net_if_insert(ai)) {
        goto ERR_3;
    }

    net_if_hold(ai->ifp);

    return (void *)ai;

ERR_3:
    lune_assert(!pthread_spin_destroy(&ai->lock));

ERR_2:
    lune_free_mt(ai);

ERR_1:
    return NULL;
}

int aggr_del_net_if(void *p)
{
    aggr_net_if_t *ai = (aggr_net_if_t *)p;
    int err;

    lune_assert(NULL != ai);

    pthread_spin_lock(&ai->lock);
    if (ai->curr_chan_num > 0) {
        pthread_spin_unlock(&ai->lock);
        return ERR_SET_ERR(LUNE_ERR_NET_IF_CHAN_NOT_DELETED);
    }

    pthread_spin_unlock(&ai->lock);

    if (0 != (err = aggr_net_if_remove(ai))) {
        return err;
    }

    net_if_put(ai->ifp);
    ai->ifp = NULL;
    aggr_net_if_put(ai);

    return err;
}

/*
    caller MUST guarantee aggr_add_chan() and aggr_del_chan() are 
    paired within the same thread where net_if is added
*/
void *aggr_add_chan(const char *name, net_if_t *ifp)
{
    char *p;
    char net_if_name[LUNE_MAX_SHORT_NAME_BUF_LEN], tmp_name[LUNE_MAX_SHORT_NAME_BUF_LEN];
    aggr_net_if_t *ai;
    aggr_chan_t *ac;
    int idx;

    lune_assert(NULL != name && NULL != ifp);

    if (NULL == (p = strrchr(name, '/'))) {
        ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        goto ERR_1;
    }

    idx = atoi(p + 1);
    if (idx < 0 || idx >= AGGR_NET_IF_MAX_CHAN_PER_AGGR_NUM) {
        ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        goto ERR_1;
    }

    lune_assert((p - name) < LUNE_MAX_NAME_LEN);
    memcpy(net_if_name, name, p - name);
    net_if_name[p - name] = 0;

    if (NULL == (ai = aggr_net_if_find((const char *)net_if_name))) {
        /*
            aggregated interface should be added and set aggregated prior to
            the creation of all channel interfaces
        */
        ERR_SET_ERR(LUNE_ERR_NET_IF_AGGR_NOT_ADDED);
        goto ERR_1;
    }

    pthread_spin_lock(&ai->lock);
#ifdef LUNE_BUILD_DPDK
    if ((LUNE_NET_IF_DPDK == ai->ifp->type
        && !net_if_dpdk_is_valid_chan_type(ai->ifp->net_if_data, ifp->type))
        || (LUNE_NET_IF_DPDK_QUEUE == ai->ifp->type
        && !net_if_dpdk_queue_is_valid_chan_type(ai->ifp->net_if_data, ifp->type))) {
        ERR_SET_ERR(LUNE_ERR_NET_IF_TYPE_ERR);
        goto ERR_2;
    }
#endif

    if (idx >= (int)ai->total_chan_num) {
        ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        goto ERR_2;
    }

    if (ai->curr_chan_num >= ai->total_chan_num
        || NULL != ai->chan_array[idx]) {
        ERR_SET_ERR(LUNE_ERR_ALREADY_EXIST);
        goto ERR_2;
    }

    if (0 == ai->curr_chan_num) {
        /*
            aggregated send task applies to the following cases:
            1. Non-DPDK aggregated interface + LUNE_NET_IF_CHAN channels
            2. LUNE_NET_IF_DPDK aggregated interface + LUNE_NET_IF_CHAN channels
            3. LUNE_NET_IF_DPDK_QUEUE aggregated interface + LUNE_NET_IF_CHAN channels
            but not the following cases:
            1. LUNE_NET_IF_DPDK aggregated interface + LUNE_NET_IF_DPDK_CHAN channels
            2. LUNE_NET_IF_DPDK_QUEUE aggregated interface + LUNE_NET_IF_DPDK_QUEUE_CHAN channels
        */
        if (LUNE_NET_IF_CHAN == ifp->type) {
            AGGR_NET_IF_SET_AGGR_SEND(ai);
        }
    } else {
        if ((LUNE_NET_IF_CHAN == ifp->type
            && !AGGR_NET_IF_IS_AGGR_SEND(ai))
            || (LUNE_NET_IF_CHAN != ifp->type
            && AGGR_NET_IF_IS_AGGR_SEND(ai))) {
            ERR_SET_ERR(LUNE_ERR_NET_IF_UNEXPECTED_TYPE);
            goto ERR_2;
        }
    }

    if (NULL == (ac = lune_malloc_mt(sizeof(aggr_chan_t)))) {
        goto ERR_2;
    }

    if (LUNE_NET_IF_DPDK_QUEUE_CHAN == ifp->type) {
#ifdef LUNE_BUILD_DPDK
        /*
            LUNE_NET_IF_DPDK_QUEUE_CHAN uses dpdk rx queues to
            connect to LUNE_NET_IF_DPDK_QUEUE, thus packet
            distribution among LUNE_NET_IF_DPDK_QUEUE is unneeded
        */
        ac->rx_rb = NULL;
#else
        ERR_SET_ERR(LUNE_ERR_NOT_SUPPORTED);
        goto ERR_3;
#endif
    } else {
        /* LUNE_NET_IF_CHAN or LUNE_NET_IF_DPDK_CHAN */
        sprintf(tmp_name, "rx ringbuf %s", name);
        if (NULL == (ac->rx_rb = ringbuf_create_buf(tmp_name,
            AGGR_CHAN_RX_RB_PKT_NUM, AGGR_CHAN_RX_RB_PKT_SIZE))) {
            goto ERR_3;
        }
    }

    ifp->mtu = ai->ifp->mtu;

    if (AGGR_NET_IF_IS_AGGR_SEND(ai)) {
        sprintf(tmp_name, "tx msgqueue %s", name);
        if (NULL == (ac->tx_mq = msgqueue_create_queue(tmp_name,
            AGGR_CHAN_TX_MSGQUEUE_SIZE))) {
            goto ERR_4;
        }
    } else {
        /*
            LUNE_NET_IF_DPDK_CHAN and LUNE_NET_IF_DPDK_QUEUE_CHAN use
            dpdk tx queue instead
        */
        ac->tx_mq = NULL;
    }

    ai->curr_chan_num++;
    ai->chan_array[idx] = ac;
    strcpy(ac->name, name);
    ac->curr_frm = NULL;
    ac->idx = idx;
    /* no need to hold ai, all managed by aggr_add_net_if()/aggr_del_net_if() */
    ac->aip = ai;
    ac->ifp = ifp;
    pthread_spin_unlock(&ai->lock);

    aggr_net_if_find_done(ai);

    return (void *)ac;

ERR_4:
    if (ifp->type != LUNE_NET_IF_DPDK_QUEUE_CHAN) {
        ringbuf_delete_buf(ac->rx_rb);
        ac->rx_rb = NULL;
    }

ERR_3:
    lune_free_mt(ac);

ERR_2:
    pthread_spin_unlock(&ai->lock);
    aggr_net_if_find_done(ai);

ERR_1:
    return NULL;
}

int aggr_del_chan(void *p)
{
    aggr_chan_t *ac = (void *)p;
    aggr_net_if_t *ai = ac->aip;

    lune_assert(ac != NULL && ai != NULL);

    if (NET_IF_IS_ACTIVE(ai->ifp)) {
        /* aggregated interface should be disabled first */
        return ERR_SET_ERR(LUNE_ERR_NET_IF_AGGR_NOT_DISABLED);
    }

    pthread_spin_lock(&ai->lock);
    ai->chan_array[ac->idx] = NULL;
    ai->curr_chan_num--;

    if (NULL != ac->tx_mq) {
        msgqueue_delete_queue(ac->tx_mq);
        ac->tx_mq = NULL;
    }

    if (ac->ifp->type != LUNE_NET_IF_DPDK_QUEUE_CHAN) {
        ringbuf_delete_buf(ac->rx_rb);
        ac->rx_rb = NULL;
    }

    lune_free_mt(ac);
    pthread_spin_unlock(&ai->lock);

    return 0;
}

void aggr_enable_chan(void *p)
{
    aggr_chan_t *ac = (void *)p;
    aggr_net_if_t *ai = ac->aip;

    lune_assert(ac != NULL && ai != NULL);
    lune_assert((int)ai->total_chan_num > lune_atomic32_get(&ai->curr_active_chan_num));

    lune_atomic32_inc(&ai->curr_active_chan_num);
}

void aggr_disable_chan(void *p)
{
    aggr_chan_t *ac = (void *)p;
    aggr_net_if_t *ai = ac->aip;

    lune_assert(ac != NULL && ai != NULL);
    lune_assert(0 < lune_atomic32_get(&ai->curr_active_chan_num));

    lune_atomic32_dec(&ai->curr_active_chan_num);
}

int aggr_chan_send(void *acp, const unsigned char *buf, unsigned int len, pbuf_t *pbuf)
{
    aggr_chan_t *ac = (aggr_chan_t *)acp;
    unsigned char *w_buf;

    if (pbuf != NULL) {
        if (PBUF_IS_REF(pbuf)) {
            if (NULL == (w_buf = msgqueue_get_write_buf(ac->tx_mq,
                sizeof(aggr_chan_tx_hdr_t) + sizeof(pbuf_t **)))) {
                lune_log_once(LUNE_INFO, "failed to send aggregated packet to %s: %s", 
                    ac->aip->name, ERR_GET_ERR_STR(ERR_SET_ERR(LUNE_ERR_BUF_FULL)));
                return ERR_SET_ERR(LUNE_ERR_BUF_FULL);
            }

            ((aggr_chan_tx_hdr_t *)w_buf)->type = AGGR_CHAN_TX_PBUF_PTR;
            ((aggr_chan_tx_hdr_t *)w_buf)->len = len;
            *(pbuf_t **)((aggr_chan_tx_hdr_t *)w_buf)->val = pbuf;
            PBUF_SET_ETH_HDR(pbuf, PBUF_GET_HDR(pbuf));
            pbuf_hold(pbuf);
        } else {
            if (NULL == (w_buf = msgqueue_get_write_buf(ac->tx_mq,
                sizeof(aggr_chan_tx_hdr_t) + sizeof(aggr_chan_tx_pbuf_pkt_hdr_t) + len))) {
                lune_log_once(LUNE_INFO, "failed to send aggregated packet to %s: %s", 
                    ac->aip->name, ERR_GET_ERR_STR(ERR_SET_ERR(LUNE_ERR_BUF_FULL)));
                return ERR_GET_LAST_ERR();
            }

            ((aggr_chan_tx_hdr_t *)w_buf)->type = AGGR_CHAN_TX_PBUF_PKT;
            ((aggr_chan_tx_hdr_t *)w_buf)->len = len;
            ((aggr_chan_tx_pbuf_pkt_hdr_t *)((aggr_chan_tx_hdr_t *)w_buf)->val)->pkt_info = pbuf->pkt_info;
            memcpy(((aggr_chan_tx_hdr_t *)w_buf)->val
                + sizeof(aggr_chan_tx_pbuf_pkt_hdr_t), buf, len);
        }
    } else {
        if (NULL == (w_buf = msgqueue_get_write_buf(ac->tx_mq,
            sizeof(aggr_chan_tx_hdr_t) + len))) {
            lune_log_once(LUNE_INFO, "failed to send aggregated packet to %s: %s", 
                ac->aip->name, ERR_GET_ERR_STR(ERR_SET_ERR(LUNE_ERR_BUF_FULL)));
            return ERR_GET_LAST_ERR();
        }

        ((aggr_chan_tx_hdr_t *)w_buf)->type = AGGR_CHAN_TX_PKT;
        ((aggr_chan_tx_hdr_t *)w_buf)->len = len;
        memcpy(((aggr_chan_tx_hdr_t *)w_buf)->val, buf, len);
    }

    msgqueue_write_buf_done(ac->tx_mq);
    lune_atomic32_inc(&ac->aip->tx_pkt_cnt);

    return 0;
}

void aggr_chan_recv_done(void *acp)
{
    aggr_chan_rx_hdr_t *acrh;

    acrh = (aggr_chan_rx_hdr_t *)((aggr_chan_t *)acp)->curr_frm;
    if (AGGR_CHAN_RX_PTR == acrh->type) {
        net_if_t *ifp = ((aggr_net_if_t *)(((aggr_chan_t *)acp)->aip))->ifp;
        /* free packet */
        ifp->drv->recv_free_pkt(ifp->net_if_data, acrh->buf, acrh->data);
    }

    ringbuf_read_frm_done(((aggr_chan_t *)acp)->rx_rb, (unsigned char *)acrh);
}

void aggr_chan_recv_pkts_done(void *acp, unsigned char *frm)
{
#ifdef LUNE_DEBUG
    lune_assert(NULL == ((aggr_chan_t *)acp)->curr_frm);
    lune_assert(NULL == ((aggr_chan_t *)acp)->rx_rb);
#endif
    if (AGGR_CHAN_RX_PTR == ((aggr_chan_rx_hdr_t *)frm)->type) {
        net_if_t *ifp = ((aggr_net_if_t *)(((aggr_chan_t *)acp)->aip))->ifp;
        /* free packet */
        ifp->drv->recv_free_pkt(ifp->net_if_data,
            ((aggr_chan_rx_hdr_t *)frm)->buf, ((aggr_chan_rx_hdr_t *)frm)->data);
    }
}

net_if_t *aggr_chan_get_aggr_ifp(void *acp)
{
    return ((aggr_chan_t *)acp)->aip->ifp;
}

unsigned int aggr_chan_get_id(void *acp)
{
    return ((aggr_chan_t *)acp)->idx;
}

unsigned int aggr_chan_get_aggr_chan_num(void *acp)
{
    return ((aggr_chan_t *)acp)->aip->total_chan_num;
}

static inline int aggr_net_if_recv_dma(aggr_net_if_t *ai,
    unsigned char *buf, unsigned int len, unsigned int idx)
{
    aggr_chan_t *ac;
    aggr_chan_rx_hdr_t *acrh;

    ac = ai->chan_array[idx];
    if (unlikely(NULL == ac)) {
        lune_log(LUNE_INFO, "channel %d not ready on %s",
            idx, ai->name, ERR_GET_ERR_STR(ERR_SET_ERR(LUNE_ERR_NOT_READY)));
        return ERR_GET_LAST_ERR();
    }

    if (NULL == (acrh = (aggr_chan_rx_hdr_t *)ringbuf_get_write_frm(ac->rx_rb,
        sizeof(aggr_chan_rx_hdr_t)))) {
        lune_log_once(LUNE_INFO, "failed to send aggregated packet to %s: %s",
            ac->name, ERR_GET_ERR_STR(ERR_SET_ERR(LUNE_ERR_BUF_FULL)));
        return ERR_GET_LAST_ERR();
    }

    AGGR_CHAN_BUILD_RX_PTR_HDR(acrh, len, buf);
    ringbuf_write_frm_done(ac->rx_rb, (unsigned char *)acrh);

    return 0;
}

static inline void aggr_net_if_recv_cpy(aggr_net_if_t *ai,
    const unsigned char *buf, unsigned int len, unsigned int idx)
{
    aggr_chan_t *ac;
    aggr_chan_rx_hdr_t *acrh;

    ac = ai->chan_array[idx];
    if (unlikely(NULL == ac)) {
        lune_log(LUNE_INFO, "channel %d not ready on %s", 
            idx, ai->name, ERR_GET_ERR_STR(ERR_SET_ERR(LUNE_ERR_NOT_READY)));
        return;
    }

    if (NULL == (acrh = (aggr_chan_rx_hdr_t *)ringbuf_get_write_frm(ac->rx_rb,
        sizeof(aggr_chan_rx_hdr_t) + len))) {
        lune_log_once(LUNE_INFO, "failed to send aggregated packet to %s: %s", 
            ac->name, ERR_GET_ERR_STR(ERR_SET_ERR(LUNE_ERR_BUF_FULL)));
        return;
    }

    AGGR_CHAN_BUILD_RX_PKT_HDR(acrh, len, buf);
    ringbuf_write_frm_done(ac->rx_rb, (unsigned char *)acrh);
}

static inline int aggr_net_if_ip_client_recv(aggr_net_if_t *ai, unsigned char *buf, unsigned int len)
{
    lune_eth_hdr_t *ethh = (lune_eth_hdr_t *)buf;
    lune_vlan_field_t *vf1, *vf2;
    unsigned int i, idx;
    unsigned short type, hdr_len;
    int err, last_err = 0;

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
            if (unlikely(ETH_TYPE_VLAN_N == type)) {
                break;
            }
        }

        goto TYPE_PARSING;
    case ETH_TYPE_ARP_N:
        goto BROADCAST;
    case ETH_TYPE_IPV4_N:
    {
        const lune_ipv4_hdr_t *ipv4h = (const lune_ipv4_hdr_t *)(buf + hdr_len);

        if (IPV4_IS_BROADCAST_IP(ipv4h->dst_addr)) {
            goto BROADCAST;
        }

        idx = (unsigned int)(((lune_ntohl(ipv4h->dst_addr) - ai->ip.start_ip.ipv4)
            / ai->ip.step) % ai->total_chan_num);
        if (0 != (err = aggr_net_if_recv_dma(ai, buf, len, idx))) {
            g_aggr_curr_ifp->drv->recv_done(g_aggr_curr_ifp->net_if_data);
        }

        return err;
    }
    case ETH_TYPE_IPV6_N:
    {
        const lune_ipv6_hdr_t *ipv6h = (const lune_ipv6_hdr_t *)(buf + hdr_len);
        idx = (unsigned int)(((lune_ntohl(ipv6h->dst_addr.addr[3]) - ai->ip.start_ip.ipv6.addr[3])
            / ai->ip.step) % ai->total_chan_num);
        if (0 != (err = aggr_net_if_recv_dma(ai, buf, len, idx))) {
            g_aggr_curr_ifp->drv->recv_done(g_aggr_curr_ifp->net_if_data);
        }

        return err;
    }
    default:
        break;
    }

    g_aggr_curr_ifp->drv->recv_done(g_aggr_curr_ifp->net_if_data);
    return 0;

BROADCAST:
    if (!AGGR_NET_IF_IS_REFCNT_AVAIL(ai)) {
        for (i = 0; i < ai->total_chan_num; i++) {
            aggr_net_if_recv_cpy(ai, buf, len, i);
        }

        g_aggr_curr_ifp->drv->recv_done(g_aggr_curr_ifp->net_if_data);
        return 0;
    }

    for (i = 0; i < ai->total_chan_num; i++) {
        if (0 != (err = aggr_net_if_recv_dma(ai, buf, len, i))) {
            last_err = err;
        }
    }

    g_aggr_curr_ifp->drv->recv_done(g_aggr_curr_ifp->net_if_data);
    return last_err;
}

static inline int aggr_net_if_ip_server_recv(aggr_net_if_t *ai, unsigned char *buf, unsigned int len)
{
    lune_eth_hdr_t *ethh = (lune_eth_hdr_t *)buf;
    lune_vlan_field_t *vf1, *vf2;
    unsigned int i, idx;
    unsigned short type, hdr_len;
    int err, last_err = 0;

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
            if (unlikely(ETH_TYPE_VLAN_N == type)) {
                break;
            }
        }

        goto TYPE_PARSING;
    case ETH_TYPE_ARP_N:
        goto BROADCAST;
    case ETH_TYPE_IPV4_N:
    {
        const lune_ipv4_hdr_t *ipv4h = (const lune_ipv4_hdr_t *)(buf + hdr_len);

        if (IPV4_IS_BROADCAST_IP(ipv4h->dst_addr)) {
            goto BROADCAST;
        }

        idx = (unsigned int)(((lune_ntohl(ipv4h->src_addr) - ai->ip.start_ip.ipv4)
            / ai->ip.step) % ai->total_chan_num);
        if (0 != (err = aggr_net_if_recv_dma(ai, buf, len, idx))) {
            g_aggr_curr_ifp->drv->recv_done(g_aggr_curr_ifp->net_if_data);
        }

        return err;
    }
    case ETH_TYPE_IPV6_N:
    {
        const lune_ipv6_hdr_t *ipv6h = (const lune_ipv6_hdr_t *)(buf + hdr_len);
        idx = (unsigned int)(((lune_ntohl(ipv6h->src_addr.addr[3]) - ai->ip.start_ip.ipv6.addr[3])
            / ai->ip.step) % ai->total_chan_num);
        if (0 != (err = aggr_net_if_recv_dma(ai, buf, len, idx))) {
            g_aggr_curr_ifp->drv->recv_done(g_aggr_curr_ifp->net_if_data);
        }

        return err;
    }
    default:
        break;
    }

    g_aggr_curr_ifp->drv->recv_done(g_aggr_curr_ifp->net_if_data);
    return 0;

BROADCAST:
    if (!AGGR_NET_IF_IS_REFCNT_AVAIL(ai)) {
        for (i = 0; i < ai->total_chan_num; i++) {
            aggr_net_if_recv_cpy(ai, buf, len, i);
        }

        g_aggr_curr_ifp->drv->recv_done(g_aggr_curr_ifp->net_if_data);
        return 0;
    }

    for (i = 0; i < ai->total_chan_num; i++) {
        if (0 != (err = aggr_net_if_recv_dma(ai, buf, len, i))) {
            last_err = err;
        }
    }

    g_aggr_curr_ifp->drv->recv_done(g_aggr_curr_ifp->net_if_data);
    return last_err;
}

static inline int aggr_net_if_mac_client_recv(aggr_net_if_t *ai, unsigned char *buf, unsigned int len)
{
    lune_eth_hdr_t *ethh = (lune_eth_hdr_t *)buf;
    unsigned int i, idx;
    lune_vlan_field_t *vf1, *vf2;
    unsigned short type, hdr_len;
    unsigned long long mac;
    int err, last_err = 0;

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
            if (unlikely(ETH_TYPE_VLAN_N == type)) {
                break;
            }
        }

        goto TYPE_PARSING;
    case ETH_TYPE_ARP_N:
        goto BROADCAST;
    default:
        LUNE_MAC_TO_LL(ethh->dst_mac, mac);
        if (LUNE_BROADCAST_MAC_LL == mac) {
            goto BROADCAST;
        }

        idx = (unsigned int)(((mac - ai->mac.start_mac) / ai->mac.step) % ai->total_chan_num);
        if (0 != (err = aggr_net_if_recv_dma(ai, buf, len, idx))) {
            g_aggr_curr_ifp->drv->recv_done(g_aggr_curr_ifp->net_if_data);
        }

        return err;
    }

    g_aggr_curr_ifp->drv->recv_done(g_aggr_curr_ifp->net_if_data);
    return 0;

BROADCAST:
    if (!AGGR_NET_IF_IS_REFCNT_AVAIL(ai)) {
        for (i = 0; i < ai->total_chan_num; i++) {
            aggr_net_if_recv_cpy(ai, buf, len, i);
        }

        g_aggr_curr_ifp->drv->recv_done(g_aggr_curr_ifp->net_if_data);
        return 0;
    }

    for (i = 0; i < ai->total_chan_num; i++) {
        if (0 != (err = aggr_net_if_recv_dma(ai, buf, len, i))) {
            last_err = err;
        }
    }

    g_aggr_curr_ifp->drv->recv_done(g_aggr_curr_ifp->net_if_data);
    return last_err;
}

static inline int aggr_net_if_mac_server_recv(aggr_net_if_t *ai, unsigned char *buf, unsigned int len)
{
    lune_eth_hdr_t *ethh = (lune_eth_hdr_t *)buf;
    unsigned int i, idx;
    lune_vlan_field_t *vf1, *vf2;
    unsigned short type, hdr_len;
    unsigned long long mac;
    int err, last_err = 0;

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
            if (unlikely(ETH_TYPE_VLAN_N == type)) {
                break;
            }
        }

        goto TYPE_PARSING;
    case ETH_TYPE_ARP_N:
        goto BROADCAST;
    default:
        LUNE_MAC_TO_LL(ethh->dst_mac, mac);
        if (LUNE_BROADCAST_MAC_LL == mac) {
            goto BROADCAST;
        }

        LUNE_MAC_TO_LL(ethh->src_mac, mac);
        idx = (unsigned int)(((mac - ai->mac.start_mac) / ai->mac.step) % ai->total_chan_num);
        if (0 != (err = aggr_net_if_recv_dma(ai, buf, len, idx))) {
            g_aggr_curr_ifp->drv->recv_done(g_aggr_curr_ifp->net_if_data);
        }

        return err;
    }

    g_aggr_curr_ifp->drv->recv_done(g_aggr_curr_ifp->net_if_data);
    return 0;

BROADCAST:
    if (!AGGR_NET_IF_IS_REFCNT_AVAIL(ai)) {
        for (i = 0; i < ai->total_chan_num; i++) {
            aggr_net_if_recv_cpy(ai, buf, len, i);
        }

        g_aggr_curr_ifp->drv->recv_done(g_aggr_curr_ifp->net_if_data);
        return 0;
    }

    for (i = 0; i < ai->total_chan_num; i++) {
        if (0 != (err = aggr_net_if_recv_dma(ai, buf, len, i))) {
            last_err = err;
        }
    }

    g_aggr_curr_ifp->drv->recv_done(g_aggr_curr_ifp->net_if_data);
    return last_err;
}

static inline int aggr_net_if_cust_recv(aggr_net_if_t *ai, unsigned char *buf, unsigned int len)
{
    unsigned int i, idx;
    int err, last_err = 0;

    idx = ai->cust.dist(ai->cust.data, buf, len);
    if (ai->total_chan_num > idx) {
        if (0 != (err = aggr_net_if_recv_dma(ai, buf, len, idx))) {
            g_aggr_curr_ifp->drv->recv_done(g_aggr_curr_ifp->net_if_data);
        }

        return err;
    }

    if (ai->total_chan_num == idx) {
        goto BROADCAST;
    }

    if (LUNE_NET_IF_AGGR_RECV_DIST_DROP == idx) {
        g_aggr_curr_ifp->drv->recv_done(g_aggr_curr_ifp->net_if_data);
        return 0;
    }

    return ERR_SET_ERR(LUNE_ERR_APP_INTERNAL);

BROADCAST:
    if (!AGGR_NET_IF_IS_REFCNT_AVAIL(ai)) {
        for (i = 0; i < ai->total_chan_num; i++) {
            aggr_net_if_recv_cpy(ai, buf, len, i);
        }

        g_aggr_curr_ifp->drv->recv_done(g_aggr_curr_ifp->net_if_data);
        return 0;
    }

    for (i = 0; i < ai->total_chan_num; i++) {
        if (0 != (err = aggr_net_if_recv_dma(ai, buf, len, i))) {
            last_err = err;
        }
    }

    g_aggr_curr_ifp->drv->recv_done(g_aggr_curr_ifp->net_if_data);
    return last_err;
}

int aggr_net_if_recv(void *ai, unsigned char *buf, unsigned int len)
{
    if (unlikely((int)((aggr_net_if_t *)ai)->total_chan_num
        != lune_atomic32_get(&((aggr_net_if_t *)ai)->curr_active_chan_num))) {
        /* receiving won't start until all channel interfaces are up and running */
        g_aggr_curr_ifp->drv->recv_done(g_aggr_curr_ifp->net_if_data);
        return ERR_SET_ERR(LUNE_ERR_NET_IF_CHAN_NOT_ENABLED);
    }

    switch (AGGR_NET_IF_GET_TYPE(ai)) {
    case LUNE_NET_IF_AGGR_IP_CLIENT:
        return aggr_net_if_ip_client_recv((aggr_net_if_t *)ai, buf, len);
    case LUNE_NET_IF_AGGR_IP_SERVER:
        return aggr_net_if_ip_server_recv((aggr_net_if_t *)ai, buf, len);
    case LUNE_NET_IF_AGGR_MAC_CLIENT:
        return aggr_net_if_mac_client_recv((aggr_net_if_t *)ai, buf, len);
    case LUNE_NET_IF_AGGR_MAC_SERVER:
        return aggr_net_if_mac_server_recv((aggr_net_if_t *)ai, buf, len);
    case LUNE_NET_IF_AGGR_CUSTOM:
        return aggr_net_if_cust_recv((aggr_net_if_t *)ai, buf, len);
    default:
        lune_assert(0);
        g_aggr_curr_ifp->drv->recv_done(g_aggr_curr_ifp->net_if_data);
        return ERR_SET_ERR(LUNE_ERR_NET_IF_INTERNAL);
    }
}

int aggr_is_net_if_ready(void *ai)
{
    if ((int)((aggr_net_if_t *)ai)->total_chan_num
        != lune_atomic32_get(&((aggr_net_if_t *)ai)->curr_active_chan_num)) {
        return 0;
    }

    return 1;
}

void *aggr_net_if_get_chan_data(void *ai, unsigned int idx)
{
#ifdef LUNE_DEBUG
    lune_assert(idx < ((aggr_net_if_t *)ai)->total_chan_num);
#endif
    return (((aggr_net_if_t *)ai)->chan_array[idx])->ifp->net_if_data;
}

static void aggr_net_if_send(aggr_net_if_t *ai)
{
    unsigned int len;
    int err;
    unsigned int i;
    net_if_t *ifp = ai->ifp;

    if (unlikely((int)ai->total_chan_num != lune_atomic32_get(&ai->curr_active_chan_num))) {
        /* sending won't start until all channel interfaces are up and running */
        return;
    }

    while (lune_atomic32_get(&ai->tx_pkt_cnt) > 0) {
        for (i = 0; i < ai->total_chan_num; i++) {
            aggr_chan_tx_hdr_t *hdr;

            while (!msgqueue_get_read_buf(ai->chan_array[i]->tx_mq,
                (unsigned char **)&hdr, &len)) {

                if (ifp->max_tx_data_rate_per_ms != NET_IF_MAX_TX_DATA_RATE_UNLIMITED
                    && ifp->tx_rt_data_per_ms >= ifp->max_tx_data_rate_per_ms) {
                    /*
                        msgqueue_read_buf_done() unneeded as it will be attempted
                        next time
                    */
                    ERR_SET_ERR(LUNE_ERR_EXCEED_LIMITS);
                    return;
                }

                switch (hdr->type) {
                case AGGR_CHAN_TX_PKT:
                    if (0 != (err = ifp->drv->send(ifp->net_if_data, hdr->val, hdr->len))) {
                        lune_log_once(LUNE_INFO, "failed to send aggregated packet to %s: %s", 
                            ai->chan_array[i]->name, ERR_GET_LAST_ERR_STR());
                        /*
                            msgqueue_read_buf_done() unneeded as it will be attempted
                            next time
                        */
                        return;
                    }

                    /* capture sent packets if enabled */   
                    NET_IF_CAP_PKT(ifp, hdr->val, hdr->len);
                    break;
                case AGGR_CHAN_TX_PBUF_PTR:
                {
                    pbuf_t *pbuf = *(pbuf_t **)hdr->val;

                    NET_IF_SET_CURR_TX_PBUF(pbuf);
                    if (0 != (err = ifp->drv->send(ifp->net_if_data,
                        PBUF_GET_ETH_HDR(pbuf), hdr->len))) {
                        NET_IF_SET_CURR_TX_PBUF(NULL);
                        lune_log_once(LUNE_INFO, "failed to send aggregated packet to %s: %s", 
                            ai->chan_array[i]->name, ERR_GET_LAST_ERR_STR());
                        /*
                            msgqueue_read_buf_done() unneeded as it will be attempted
                            next time
                        */
                        return;
                    }
                    NET_IF_SET_CURR_TX_PBUF(NULL);

                    /* capture sent packets if enabled */
                    NET_IF_CAP_PKT(ifp, PBUF_GET_ETH_HDR(pbuf), hdr->len);
                    pbuf_put(pbuf);
                    break;
                }
                case AGGR_CHAN_TX_PBUF_PKT:
                {
                    pbuf_t pbuf;

                    /* only initialize fields that may be needed by send interface */
                    pbuf.pkt_info =
                        ((aggr_chan_tx_pbuf_pkt_hdr_t *)(hdr->val))->pkt_info;
                    PBUF_SET_UNREF(&pbuf);

                    NET_IF_SET_CURR_TX_PBUF(&pbuf);
                    if (0 != (err = ifp->drv->send(ifp->net_if_data,
                        hdr->val + sizeof(aggr_chan_tx_pbuf_pkt_hdr_t), hdr->len))) {
                        NET_IF_SET_CURR_TX_PBUF(NULL);
                        lune_log_once(LUNE_INFO, "failed to send aggregated packet to %s: %s", 
                            ai->chan_array[i]->name, ERR_GET_LAST_ERR_STR());
                        /*
                            msgqueue_read_buf_done() unneeded as it will be attempted
                            next time
                        */
                        return;
                    }
                    NET_IF_SET_CURR_TX_PBUF(NULL);

                    /* capture sent packets if enabled */
                    NET_IF_CAP_PKT(ifp, hdr->val + sizeof(aggr_chan_tx_pbuf_pkt_hdr_t), hdr->len);
                    break;
                }
                default:
                    lune_assert(0);
                    return;
                }

                ifp->tx_rt_data_per_ms += hdr->len;
                msgqueue_read_buf_done(ai->chan_array[i]->tx_mq);
                lune_atomic32_dec(&ai->tx_pkt_cnt);
            }
        }
    }
}

int aggr_enable_net_if(void *p)
{
    aggr_net_if_t *ai = (aggr_net_if_t *)p;

    lune_assert(NULL != ai);

    pthread_spin_lock(&ai->lock);
    if (ai->curr_chan_num != ai->total_chan_num) {
            pthread_spin_unlock(&ai->lock);
            ERR_SET_ERR(LUNE_ERR_NET_IF_CHAN_NOT_ADDED);
            goto ERR_1;
    }
    pthread_spin_unlock(&ai->lock);

    if (AGGR_NET_IF_IS_AGGR_SEND(ai)) {
        if (LUNE_INVALID_ID == (ai->tx_task_id = sched_add_task(ai->ifp->name,
            (lune_task_func_t)aggr_net_if_send, (void *)ai, SCHED_PRIO_NORMAL))) {
            goto ERR_1;
        }
    }

    return 0;

ERR_1:
    return ERR_GET_LAST_ERR();
}

int aggr_disable_net_if(void *p)
{
    aggr_net_if_t *ai = (aggr_net_if_t *)p;

    lune_assert(NULL == ai->ifp->sk);
    lune_assert(NULL != ai);

    if (0 != lune_atomic32_get(&ai->curr_active_chan_num)) {
        /* all channel interfaces should be disabled first */
        return ERR_SET_ERR(LUNE_ERR_NET_IF_CHAN_NOT_DISABLED);
    }

    pthread_spin_lock(&ai->lock);
    lune_assert(ai->curr_chan_num == ai->total_chan_num);
    pthread_spin_unlock(&ai->lock);

    if (AGGR_NET_IF_IS_AGGR_SEND(ai)) {
        (void)sched_del_task(ai->tx_task_id);
        ai->tx_task_id = LUNE_INVALID_ID;
    } else {
        lune_assert(LUNE_INVALID_ID == ai->tx_task_id);
    }

    return 0;
}

static int aggr_net_if_hash(aggr_net_if_t *ai)
{
    char *p;
    int i;

    lune_assert(0 != ai->name[0]);

    i = 0;
    p = ai->name;
    while (p[i]) {
        ++i;
    }

    return p[i - 1] & AGGR_NET_IF_HTABLE_MASK;
}

static int aggr_net_if_compare(aggr_net_if_t *ai1, aggr_net_if_t *ai2)
{
    return strcmp(ai1->name, ai2->name);
}

int aggr_init(void)
{
    if (NULL == (s_aggr_net_if_htable = htable_create_table_mt("aggregated interface hash table", 
        (htable_hash_func_t)aggr_net_if_hash,
        (htable_compare_func_t)aggr_net_if_compare,
        (htable_hold_func_t)aggr_net_if_hold,
        (htable_put_func_t)aggr_net_if_put,
        offsetof(aggr_net_if_t, node),
        AGGR_NET_IF_HTABLE_SIZE))) {
        return ERR_GET_LAST_ERR();
    }

    return 0;
}

void aggr_fini(void)
{
    lune_assert(!htable_delete_table_mt(s_aggr_net_if_htable));
    s_aggr_net_if_htable = NULL;
}
