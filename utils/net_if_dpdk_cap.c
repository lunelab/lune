/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2024 Lune Reseau, Inc.
 */

#include "lune/mem.h"
#include "lune/os/linux.h"

#include "drv/dpdk/net_if_dpdk.h"
#include "err/err.h"
#include "nrt/nrt.h"
#include "utils/cap.h"
#include "utils/net_if_dpdk_cap.h"

static inline void net_if_dpdk_cap_init_and_hold(net_if_dpdk_cap_t *cap)
{
    lune_atomic32_set(&cap->ref_cnt, 1);
}

static inline void net_if_dpdk_cap_hold(net_if_dpdk_cap_t *cap)
{
    lune_atomic32_inc(&cap->ref_cnt);
}

static inline void net_if_dpdk_cap_put(net_if_dpdk_cap_t *cap)
{
    if (lune_atomic32_dec_is_zero(&cap->ref_cnt)) {
        lune_free_mt(cap);
    }
}

static inline void net_if_dpdk_cap_write_pkt_to_file(net_if_dpdk_cap_pkt_t *pkt,
    net_if_dpdk_cap_t *cap)
{
    int err;
    unsigned short len;

    switch (pkt->type) {
    case NET_IF_DPDK_CAP_NODE_TYPE_PKT:
        len = pkt->len;
        if (0 != (err = cap_write_pkt_to_file(cap->cap_fp,
            &pkt->tv, pkt->val, len))) {
            if (-LUNE_ERR_BUF_FULL == err) {
                NET_IF_DPDK_CAP_SET_REACH_LIMIT(cap);
            } else {
                lune_log(LUNE_INFO, "failed to write packet to %s: %s",
                    cap_get_file_name(cap->cap_fp), ERR_GET_ERR_STR(err));
            }
            return;
        }
        break;
    case NET_IF_DPDK_CAP_NODE_TYPE_MBUF:
    {
        struct rte_mbuf *mbuf = *(struct rte_mbuf **)pkt->val;
        len = rte_pktmbuf_data_len(mbuf);
        if (0 != (err = cap_write_pkt_to_file(cap->cap_fp,
            &pkt->tv, rte_pktmbuf_mtod(mbuf, unsigned char *), len))) {
            if (-LUNE_ERR_BUF_FULL == err) {
                NET_IF_DPDK_CAP_SET_REACH_LIMIT(cap);
            } else {
                lune_log(LUNE_INFO, "failed to write packet to %s: %s",
                    cap_get_file_name(cap->cap_fp), ERR_GET_ERR_STR(err));
            }
            net_if_dpdk_mbuf_put(mbuf);
            return;
        }
        net_if_dpdk_mbuf_put(mbuf);
        break;
    }
    default:
        lune_assert(0);
        return;
    }

    if (pkt->is_in) {
        NET_IF_DPDK_CAP_INC_WRITTEN_PKT_IN(cap);
        NET_IF_DPDK_CAP_ADD_WRITTEN_BYTE_IN(cap, len);
        NET_IF_DPDK_CAP_DEC_CACHED_PKT_IN(cap);
        NET_IF_DPDK_CAP_SUB_CACHED_BYTE_IN(cap, len);
    } else {
        NET_IF_DPDK_CAP_INC_WRITTEN_PKT_OUT(cap);
        NET_IF_DPDK_CAP_ADD_WRITTEN_BYTE_OUT(cap, len);
        NET_IF_DPDK_CAP_DEC_CACHED_PKT_OUT(cap);
        NET_IF_DPDK_CAP_SUB_CACHED_BYTE_OUT(cap, len);
    }
}

static void *net_if_dpdk_cap_pkt(net_if_dpdk_cap_t *cap)
{
    unsigned int sleep_usecs = 500;
    net_if_dpdk_cap_pkt_t *pkt = NULL, *p;

    while (1) {
        if (NET_IF_DPDK_CAP_IS_STOPPED(cap)) {
            lune_assert(NULL == lune_atomic_ptr_get((void **)&cap->curr_pkt));
            goto STOP_CAP;
        }

        if (NULL != cap->pkt_list.next) {
            /* first packet */
            pkt = cap->pkt_list.next;
            break;
        }

        usleep(sleep_usecs);
    }

    while (1) {
        net_if_dpdk_cap_write_pkt_to_file(pkt, cap);

        while (NULL == pkt->next
            && !NET_IF_DPDK_CAP_IS_STOPPED(cap)) {
            usleep(sleep_usecs);
        }

        if (NET_IF_DPDK_CAP_IS_STOPPED(cap)) {
            lune_assert(NULL == lune_atomic_ptr_get((void **)&cap->curr_pkt));
            goto STOP_CAP;
        }

        p = pkt->next;
        lune_free_mt(pkt);
        pkt = p;
    }

STOP_CAP:
    while (NULL != pkt) {
        /* write cached packets before capture stopped */
#ifdef LUNE_DEBUG
        lune_assert(cap->last_pkt != &cap->pkt_list);
#endif
        if (cap->last_pkt == pkt) {
            lune_assert(NULL == pkt->next);
            lune_free_mt(pkt);
            break;
        }

        while (NULL == pkt->next) {
            usleep(sleep_usecs);
        }

        p = pkt->next;
        lune_free_mt(pkt);
        pkt = p;

        net_if_dpdk_cap_write_pkt_to_file(pkt, cap);
    }

    cap_stop(cap->cap_fp);
    cap->cap_fp = NULL;

    net_if_dpdk_cap_put(cap);      /* for thread */
    return NULL;
}

static void net_if_dpdk_cap_nrt_create_thread_resp(unsigned int type,
    const unsigned char *resp,
    unsigned int resp_len,
    int err,
    net_if_dpdk_cap_t *cap)
{
    lune_assert(NULL == cap->cap_thd);

    if (NRT_RESP_TYPE_FAILURE == type) {
        lune_log(LUNE_INFO, "failed to create thread for capturing dpdk "
            "interface: %s", ERR_GET_ERR_STR(err));
        cap_stop(cap->cap_fp);
        cap->cap_fp = NULL;
        net_if_dpdk_cap_put(cap);  /* for thread */
        net_if_dpdk_cap_put(cap);  /* for response */
        return;
    }

    if (NET_IF_DPDK_CAP_IS_STOPPED(cap)) {
        net_if_dpdk_cap_put(cap);  /* for response */
        return;
    }

    lune_assert(sizeof(void *) == resp_len);
    lune_assert(NULL != (cap->cap_thd = *(void * const *)resp));
    net_if_dpdk_cap_put(cap);  /* for response */
}

#ifdef LUNE_DEBUG
static void net_if_dpdk_cap_stats_func(net_if_dpdk_cap_t *cap)
{
    lune_log(LUNE_DBG, "%s capture: "
        "c_pkt_in: %lld "
        "c_pkt_out: %lld "
        "c_b_in: %lld "
        "c_b_out: %lld "
        "w_pkt_in: %lld "
        "w_pkt_out: %lld "
        "w_b_in: %lld "
        "w_b_out: %lld ",
        cap->name,
        cap->stats.cached_pkt_in,
        cap->stats.cached_pkt_out,
        cap->stats.cached_byte_in,
        cap->stats.cached_byte_out,
        cap->stats.written_pkt_in,
        cap->stats.written_pkt_out,
        cap->stats.written_byte_in,
        cap->stats.written_byte_out);
}
#endif

void net_if_dpdk_cap_cap_pkt(void *cap,
    const unsigned char *buf, unsigned int len, unsigned int is_in)
{
    net_if_dpdk_cap_pkt_t *curr, *prev;

    if (NET_IF_DPDK_CAP_REACH_LIMIT(cap)) {
        return;
    }

    if (NULL == (curr = lune_malloc_mt(sizeof(net_if_dpdk_cap_pkt_t) + len))) {
        lune_log_once(LUNE_INFO, "failed to capture packet for %s: %s",
            cap_get_file_name(((net_if_dpdk_cap_t *)cap)->cap_fp),
                ERR_GET_ERR_STR(ERR_GET_LAST_ERR()));
        return;
    }

    curr->next = NULL;
    curr->type = NET_IF_DPDK_CAP_NODE_TYPE_PKT;
    curr->len = len;
    curr->is_in = is_in;
    memcpy((unsigned char *)curr->val, buf, len);
    time_get_time_of_day(&curr->tv);
    lune_smp_wmb();
    prev = (net_if_dpdk_cap_pkt_t *)lune_atomic_ptr_exchange(
        (lune_atomic_ptr_t *)&((net_if_dpdk_cap_t *)cap)->curr_pkt, curr);
    if (NULL == prev) {
        /* capture stopped */
        lune_free_mt(curr);
    } else {
        if (is_in) {
            NET_IF_DPDK_CAP_INC_CACHED_PKT_IN(cap);
            NET_IF_DPDK_CAP_ADD_CACHED_BYTE_IN(cap, len);
        } else {
            NET_IF_DPDK_CAP_INC_CACHED_PKT_OUT(cap);
            NET_IF_DPDK_CAP_ADD_CACHED_BYTE_OUT(cap, len);
        }
        prev->next = curr;
    }
}

void net_if_dpdk_cap_cap_mbuf(void *cap, struct rte_mbuf *mbuf, unsigned int is_in)
{
    net_if_dpdk_cap_pkt_t *curr, *prev;

    if (NET_IF_DPDK_CAP_REACH_LIMIT(cap)) {
        return;
    }

    if (NULL == (curr = lune_malloc_mt(sizeof(net_if_dpdk_cap_pkt_t) + sizeof(struct rte_mbuf *)))) {
        lune_log_once(LUNE_INFO, "failed to capture packet for %s: %s",
            cap_get_file_name(((net_if_dpdk_cap_t *)cap)->cap_fp),
                ERR_GET_ERR_STR(ERR_GET_LAST_ERR()));
        return;
    }

    curr->next = NULL;
    curr->type = NET_IF_DPDK_CAP_NODE_TYPE_MBUF;
    curr->len = sizeof(struct rte_mbuf *);
    curr->is_in = is_in;
    *(struct rte_mbuf **)curr->val = mbuf;
    net_if_dpdk_mbuf_hold(mbuf);
    time_get_time_of_day(&curr->tv);
    lune_smp_wmb();
    prev = (net_if_dpdk_cap_pkt_t *)lune_atomic_ptr_exchange(
        (lune_atomic_ptr_t *)&((net_if_dpdk_cap_t *)cap)->curr_pkt, curr);
    if (NULL == prev) {
        /* capture stopped */
        net_if_dpdk_mbuf_put(mbuf);
        lune_free_mt(curr);
    } else {
        if (is_in) {
            NET_IF_DPDK_CAP_INC_CACHED_PKT_IN(cap);
            NET_IF_DPDK_CAP_ADD_CACHED_BYTE_IN(cap, rte_pktmbuf_data_len(mbuf));
        } else {
            NET_IF_DPDK_CAP_INC_CACHED_PKT_OUT(cap);
            NET_IF_DPDK_CAP_ADD_CACHED_BYTE_OUT(cap, rte_pktmbuf_data_len(mbuf));
        }
        prev->next = curr;
    }
}

void *net_if_dpdk_cap_start(const char *net_if_name, const char *file_name)
{
    nrt_thread_t *thd;
    net_if_dpdk_cap_t *cap;

    if (NULL == (cap = lune_malloc_mt(sizeof(net_if_dpdk_cap_t)))) {
        goto ERR_1;
    }

    strcpy(cap->name, net_if_name);

    if (NULL == (cap->cap_fp = cap_start(file_name))) {
        goto ERR_2;
    }

    cap->cap_thd = NULL;
    cap->flags = 0;
    NET_IF_DPDK_CAP_INIT_LIST(&cap->pkt_list);
    cap->last_pkt = cap->curr_pkt = &cap->pkt_list;
    memset(&cap->stats, 0x00, sizeof(cap->stats));
#ifdef LUNE_DEBUG
    lune_add_nrt_timer(&cap->stats_tmr, LUNE_TIMER_RECURRING,
        1 * LUNE_TIME_SECOND, (lune_timer_func_t)net_if_dpdk_cap_stats_func, (void *)cap);
#endif

    if (NULL == (thd = (nrt_thread_t *)nrt_get_req_buf(NRT_REQ_TYPE_CREATE_THREAD,
        sizeof(nrt_thread_t)))) {
        lune_log(LUNE_WARN, "failed to start capture on %s: %s\n",
            file_name, ERR_GET_ERR_STR(ERR_SET_ERR(LUNE_ERR_BUF_FULL)));
        goto ERR_3;
    }

    NET_IF_DPDK_CAP_SET_START(cap);

    sprintf(thd->name, "capture thread");
    thd->func = (nrt_thread_func_t)net_if_dpdk_cap_pkt;
    thd->data = cap;
    net_if_dpdk_cap_init_and_hold(cap);    /* for thread */
    nrt_set_resp((unsigned char *)thd,
        (nrt_resp_func_t)net_if_dpdk_cap_nrt_create_thread_resp, cap);
    net_if_dpdk_cap_hold(cap);             /* for response */
    net_if_dpdk_cap_hold(cap);             /* for return */

    nrt_req_buf_done();
    return (void *)cap;

ERR_3:
    cap_stop(cap->cap_fp);

ERR_2:
    lune_free_mt(cap);

ERR_1:
    return NULL;
}

void net_if_dpdk_cap_stop(void *cap)
{
#ifdef LUNE_DEBUG
    lune_del_nrt_timer(&((net_if_dpdk_cap_t *)cap)->stats_tmr);
#endif
    ((net_if_dpdk_cap_t *)cap)->last_pkt = (net_if_dpdk_cap_pkt_t *)lune_atomic_ptr_exchange(
        (lune_atomic_ptr_t *)&((net_if_dpdk_cap_t *)cap)->curr_pkt, NULL);
    lune_smp_wmb();
    NET_IF_DPDK_CAP_SET_STOP((net_if_dpdk_cap_t *)cap);
    net_if_dpdk_cap_put((net_if_dpdk_cap_t *)cap);
}
