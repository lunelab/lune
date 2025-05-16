/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2024 Lune Reseau, Inc.
 */

#include "lune/arp.h"
#include "lune/id.h"
#include "lune/ip.h"
#include "lune/log.h"
#include "lune/mem.h"
#include "lune/nb.h"
#include "lune/time.h"

#include "drv/net_if.h"
#include "lib/htable.h"
#include "kernel/time.h"
#include "kernel/timer.h"
#include "net/arp.h"
#include "net/ip.h"
#include "net/mac.h"
#include "net/nb.h"
#include "net/pbuf.h"

#define NB_HTABLE_SIZE_IN_BIT               (20)
#define NB_HTABLE_SIZE                      (1 << (NB_HTABLE_SIZE_IN_BIT))
#define NB_HTABLE_MASK                      (NB_HTABLE_SIZE - 1)

#define NB_DEFAULT_LIVE_TIME                (30 * LUNE_TIME_SECOND)
#define NB_DEFAULT_REQ_RETRANS_TIMES        (3)
#define NB_DEFAULT_REQ_RETRANS_INTVL        (1 * LUNE_TIME_SECOND)
#define NB_DEFAULT_DEQUEUE_INTVL            (1)
#define NB_DEFAULT_DEQUEUE_RETRANS_TIMES    (3)
#define NB_DEFAULT_DEQUEUE_RETRANS_INTVL    (10 * LUNE_TIME_MILLISECOND)

#define NB_REQUESTING_MAX_QUEUE_PKT_NUM     (4096)
#define NB_DEQUEUE_MAX_PKT_NUM_ONCE         (32)

#define NB_GET_ETH_TYPE(nb)                 \
    (((neighbor_t *)nb)->dst_addr.is_ipv6 ? ETH_TYPE_IPV6_N : ETH_TYPE_IPV4_N)

static __thread void *s_nb_htable = NULL;

static __thread unsigned long long s_nb_live_time;
static __thread unsigned long long s_nb_retrans_times;
static __thread unsigned long long s_nb_retrans_intvl;
static __thread void *s_nb_mem_pool;

static void nb_dequeue(neighbor_t *nb);

static void nb_expire(neighbor_t *nb);

static inline void nb_first_hold(neighbor_t *nb)
{
#ifdef LUNE_DEBUG
    lune_assert(0 == nb->ref_cnt);
#endif
    ++nb->ref_cnt;
}

static inline void nb_hold(neighbor_t *nb)
{
#ifdef LUNE_DEBUG
    lune_assert(nb->ref_cnt > 0);
#endif
    ++nb->ref_cnt;
}

static inline void nb_put(neighbor_t *nb)
{
#ifdef LUNE_DEBUG
    lune_assert(nb->ref_cnt > 0);
#endif
    if (0 == --nb->ref_cnt) {
        lune_mem_pool_free(s_nb_mem_pool, nb);
    }
}

void nb_log_error(const char *msg, const lune_ip_addr_t *addr, int err)
{
    char ip_str[LUNE_IP_MAX_ADDR_STR_LEN];

    lune_log(LUNE_WARN, "%s for neighbor %s: %s", msg,
        addr->is_ipv6 ? lune_ipv6_to_str(&addr->ipv6, ip_str, LUNE_IPV6_MAX_ADDR_STR_LEN)
            : lune_ipv4_to_str(addr->ipv4, ip_str, LUNE_IPV4_MAX_ADDR_STR_LEN),
        ERR_GET_ERR_STR(err));
}

void *nb_lookup(const lune_ip_addr_t *addr, void *ifp)
{
    neighbor_t nb;

    LUNE_IP_CPY(&nb.dst_addr, addr);
    nb.ifp = ifp;
    return htable_find((void *)&nb, s_nb_htable);
}

void nb_delete(void *nb)
{
    pbuf_t *pbuf, *pbuf2;

    if (LUNE_TIMER_IS_ADDED(((neighbor_t *)nb)->tmr)) {
        timer_del_timer(&((neighbor_t *)nb)->tmr);
    }

    if (NULL != ((neighbor_t *)nb)->ipp) {
        ip_put(((neighbor_t *)nb)->ipp);
    }

    dlist_for_each_node_safe(pbuf, pbuf2, &((neighbor_t *)nb)->pbuf_list, node) {
        lune_assert(NULL != pbuf->macp);
        dlist_del(&pbuf->node);
#ifdef LUNE_BUILD_DPDK
        if (!MAC_IS_DPDK(pbuf->macp) || !PBUF_IS_DPDK_PBUF(pbuf)) {
#endif
            mac_put((mac_t *)pbuf->macp);
            pbuf_free_pbuf(pbuf);
#ifdef LUNE_BUILD_DPDK
        } else {
            /* put mac after conditional check */
            mac_put((mac_t *)pbuf->macp);
            pbuf_dpdk_pbuf_put(pbuf);
        }
#endif
    }

    lune_assert(!htable_remove(nb, s_nb_htable));

    nb_put(nb);
}

static void nb_req_timeout(neighbor_t *nb)
{
    int err;
    ip_t *ipp;
    lune_ip_addr_t addr;

    ipp = nb->ipp;
    lune_assert(LUNE_ID_MAC == ipp->lower_type);
    lune_assert(NB_STATE_REQ == nb->state);

    if (0 == nb->retrans--) {
        ip_conv_ip(ipp, &addr);
        nb_log_error("hit maximum retransmit times", &addr, ERR_SET_ERR(LUNE_ERR_MAX_RETRIES));
        goto DELETE_NB;
    }

    if (IP_IS_DELETED(ipp)) {
        /* ip has already been deleted, remove it from neighbor table */
        goto DELETE_NB;
    }

    if (nb->dst_addr.is_ipv6) {
        err = icmpv6_send_nb_solicit(ipp, &nb->dst_addr.ipv6);
    } else {
        err = arp_send_req(ipp, nb->dst_addr.ipv4);
    }

    if (0 != err) {
        ip_conv_ip(ipp, &addr);
        nb_log_error("failed to resend neighbor request", &addr, err);
        goto DELETE_NB;
    }

    timer_add_timer(&nb->tmr, s_nb_retrans_intvl);
    return;

DELETE_NB:
    nb_delete(nb);
}

int nb_request_and_cache_pkt(const lune_ip_addr_t *dst_addr,
    ip_t *ipp, mac_t *macp, pbuf_t *pbuf)
{
    neighbor_t *nb;
    int err;

    if (NULL == (nb = lune_mem_pool_alloc(s_nb_mem_pool))) {
        err = ERR_GET_LAST_ERR();
        goto ERR_1;
    }

    dlist_init_head(&nb->pbuf_list);
    timer_init_timer(&nb->tmr,
        LUNE_TIMER_ONCE, LUNE_TIMER_RES_HIGH, (lune_timer_func_t)nb_req_timeout, nb);
    nb->ipp = ipp;
    LUNE_MAC_CPY(nb->dst_mac, g_broadcast_mac);
    nb->retrans = s_nb_retrans_times;
    LUNE_IP_CPY(&nb->dst_addr, dst_addr);
    nb->state = NB_STATE_REQ;
    nb->queue_pkt_cnt = 0;
    nb->ref_cnt = 0;
    nb->ifp = ipp->ifp;

    if (0 != (err = htable_insert((void *)nb, s_nb_htable, 1))) {
        goto ERR_2;
    }

    ip_hold(ipp);

    if (NULL != pbuf) {
#ifdef LUNE_BUILD_DPDK
        if (!MAC_IS_DPDK(macp) || !PBUF_IS_DPDK_PBUF(pbuf)) {
#endif
            if (NULL == (pbuf = pbuf_dup_pbuf(pbuf))) {
                err = ERR_GET_LAST_ERR();
                goto ERR_3;
            }
#ifdef LUNE_BUILD_DPDK
        } else {
            /* local pbuf with allocated mbuf, e.g., udp packet, tcp ACK packet */
            lune_assert(!PBUF_IS_REF(pbuf));

            if (NULL == (pbuf = pbuf_dpdk_spawn_send_pbuf(pbuf))) {
                goto ERR_3;
            }

            pbuf_dpdk_pbuf_hold(pbuf);
        }
#endif

        dlist_add_tail(&pbuf->node, &nb->pbuf_list);

        pbuf->macp = (void *)macp;
        mac_hold(macp);

        nb->queue_pkt_cnt++;
    } else {
        /* no packet to send, resolve destination mac address only */
    }

    if (dst_addr->is_ipv6) {
        err = icmpv6_send_nb_solicit(ipp, &dst_addr->ipv6);
    } else {
        err = arp_send_req(ipp, dst_addr->ipv4);
    }

    if (0 != err) {
        goto ERR_4;
    }

    timer_add_timer(&nb->tmr, s_nb_retrans_intvl);
    nb_first_hold(nb);
    return 0;

ERR_4:
    if (NULL != pbuf) {
        nb->queue_pkt_cnt--;
        dlist_del(&pbuf->node);
#ifdef LUNE_BUILD_DPDK
        if (!MAC_IS_DPDK(macp) || !PBUF_IS_DPDK_PBUF(pbuf)) {
#endif
            mac_put(macp);
            pbuf_free_pbuf(pbuf);
#ifdef LUNE_BUILD_DPDK
        } else {
            /* put mac after conditional check */
            mac_put(macp);
            pbuf_dpdk_pbuf_put(pbuf);
        }
#endif
    }

ERR_3:
    ip_put(nb->ipp);
    (void)htable_remove((void *)nb, s_nb_htable);

ERR_2:
    lune_mem_pool_free(s_nb_mem_pool, nb);

ERR_1:
    return err;
}

int nb_cache_pkt(void *nb, mac_t *macp, pbuf_t *pbuf)
{
    if (((neighbor_t *)nb)->queue_pkt_cnt >= NB_REQUESTING_MAX_QUEUE_PKT_NUM) {
        return ERR_SET_ERR(LUNE_ERR_EXCEED_LIMITS);
    }

#ifdef LUNE_BUILD_DPDK
    if (!MAC_IS_DPDK(macp) || !PBUF_IS_DPDK_PBUF(pbuf)) {
#endif
        if (NULL == (pbuf = pbuf_dup_pbuf(pbuf))) {
            return ERR_GET_LAST_ERR();
        }
#ifdef LUNE_BUILD_DPDK
    } else {
        /* local pbuf with allocated mbuf, e.g., udp packet, tcp ACK packet */
        lune_assert(!PBUF_IS_REF(pbuf));

        if (NULL == (pbuf = pbuf_dpdk_spawn_send_pbuf(pbuf))) {
            return ERR_GET_LAST_ERR();
        }

        pbuf_dpdk_pbuf_hold(pbuf);
    }
#endif

    dlist_add_tail(&pbuf->node, &((neighbor_t *)nb)->pbuf_list);
    mac_hold(macp);
    pbuf->macp = (void *)macp;

    ((neighbor_t *)nb)->queue_pkt_cnt++;

    return 0;
}

static void nb_retrans(neighbor_t *nb)
{
    pbuf_t *pbuf, *pbuf2;
    unsigned short dequeue_pkt_cnt = 0;
    int err;

    lune_assert(NULL != nb->ipp);

    dlist_for_each_node_safe(pbuf, pbuf2, &nb->pbuf_list, node) {
        unsigned long long bytes;

        if (dequeue_pkt_cnt >= NB_DEQUEUE_MAX_PKT_NUM_ONCE) {
            timer_reuse_timer(&nb->tmr,
                LUNE_TIMER_ONCE, LUNE_TIMER_RES_HIGH, (lune_timer_func_t)nb_dequeue, nb);
            timer_add_timer(&nb->tmr, NB_DEFAULT_DEQUEUE_INTVL);
            return;
        }

        bytes = PBUF_GET_PAYLOAD_LEN(pbuf) + PBUF_GET_HDR_LEN(pbuf);

        lune_assert(NULL != pbuf->macp);
        if (0 != (err = mac_output((mac_t *)pbuf->macp,
            nb->dst_mac, NB_GET_ETH_TYPE(nb), pbuf))) {
            lune_log(LUNE_INFO, "failed to send %d cached packets: %s",
                nb->queue_pkt_cnt, ERR_GET_ERR_STR(err));
            if (0 == dequeue_pkt_cnt) {
                if (0 == nb->retrans--) {
                    nb_delete(nb);
                    return;
                }

                timer_add_timer(&nb->tmr, NB_DEFAULT_DEQUEUE_RETRANS_INTVL);
                return;
            }

            nb->retrans = NB_DEFAULT_DEQUEUE_RETRANS_TIMES;
            timer_add_timer(&nb->tmr, NB_DEFAULT_DEQUEUE_RETRANS_INTVL);
            return;
        }

        nb->ipp->stats.pkt_out++;
        nb->ipp->stats.byte_out += bytes;

        dlist_del(&pbuf->node);
#ifdef LUNE_BUILD_DPDK
        if (!MAC_IS_DPDK(pbuf->macp) || !PBUF_IS_DPDK_PBUF(pbuf)) {
#endif
            mac_put((mac_t *)pbuf->macp);
            pbuf_free_pbuf(pbuf);
#ifdef LUNE_BUILD_DPDK
        } else {
            /* put mac after conditional check */
            mac_put((mac_t *)pbuf->macp);
            pbuf_dpdk_pbuf_put(pbuf);
        }
#endif

        nb->queue_pkt_cnt--;
        dequeue_pkt_cnt++;
    }

    lune_assert(0 == nb->queue_pkt_cnt);

    timer_reuse_timer(&nb->tmr,
        LUNE_TIMER_ONCE, LUNE_TIMER_RES_HIGH, (lune_timer_func_t)nb_expire, nb);
    timer_add_timer(&nb->tmr, s_nb_live_time);
}

static void nb_dequeue(neighbor_t *nb)
{
    pbuf_t *pbuf, *pbuf2;
    unsigned short dequeue_pkt_cnt = 0;
    int err;

    lune_assert(NULL != nb->ipp);

    dlist_for_each_node_safe(pbuf, pbuf2, &nb->pbuf_list, node) {
        unsigned long long bytes;

        if (dequeue_pkt_cnt >= NB_DEQUEUE_MAX_PKT_NUM_ONCE) {
            timer_add_timer(&nb->tmr, NB_DEFAULT_DEQUEUE_INTVL);
            return;
        }

        bytes = PBUF_GET_PAYLOAD_LEN(pbuf) + PBUF_GET_HDR_LEN(pbuf);

        lune_assert(NULL != pbuf->macp);
        if (0 != (err = mac_output((mac_t *)pbuf->macp,
            nb->dst_mac, NB_GET_ETH_TYPE(nb), pbuf))) {
            lune_log(LUNE_INFO, "failed to send %d cached packets: %s",
                nb->queue_pkt_cnt, ERR_GET_ERR_STR(err));
            nb->retrans = NB_DEFAULT_DEQUEUE_RETRANS_TIMES;
            timer_reuse_timer(&nb->tmr,
                LUNE_TIMER_ONCE, LUNE_TIMER_RES_HIGH, (lune_timer_func_t)nb_retrans, nb);
            timer_add_timer(&nb->tmr, NB_DEFAULT_DEQUEUE_RETRANS_INTVL);
            return;
        }

        nb->ipp->stats.pkt_out++;
        nb->ipp->stats.byte_out += bytes;

        dlist_del(&pbuf->node);
#ifdef LUNE_BUILD_DPDK
        if (!MAC_IS_DPDK(pbuf->macp) || !PBUF_IS_DPDK_PBUF(pbuf)) {
#endif
            mac_put((mac_t *)pbuf->macp);
            pbuf_free_pbuf(pbuf);
#ifdef LUNE_BUILD_DPDK
        } else {
            /* put mac after conditional check */
            mac_put((mac_t *)pbuf->macp);
            pbuf_dpdk_pbuf_put(pbuf);
        }
#endif

        nb->queue_pkt_cnt--;
        dequeue_pkt_cnt++;
    }

    lune_assert(0 == nb->queue_pkt_cnt);

    timer_reuse_timer(&nb->tmr,
        LUNE_TIMER_ONCE, LUNE_TIMER_RES_HIGH, (lune_timer_func_t)nb_expire, nb);
    timer_add_timer(&nb->tmr, s_nb_live_time);
}

static void nb_expire(neighbor_t *nb)
{
    nb_delete(nb);
}

int nb_upsert(const lune_mac_addr_t dst_mac, lune_ip_addr_t *dst_addr, void *ifp)
{
    int err = 0;
    unsigned short dequeue_pkt_cnt;
    neighbor_t *nb, nb2;
    pbuf_t *pbuf, *pbuf2;

    LUNE_IP_CPY(&nb2.dst_addr, dst_addr);
    nb2.ifp = ifp;
    if (NULL == (nb = htable_find((void *)&nb2, s_nb_htable))) {
        if (NULL == (nb = lune_mem_pool_alloc(s_nb_mem_pool))) {
            return ERR_GET_LAST_ERR();
        }

        dlist_init_head(&nb->pbuf_list);
        timer_init_timer(&nb->tmr,
            LUNE_TIMER_ONCE, LUNE_TIMER_RES_HIGH, (lune_timer_func_t)nb_expire, nb);
        nb->ipp = NULL;
        LUNE_MAC_CPY(nb->dst_mac, dst_mac);
        nb->retrans = s_nb_retrans_times;
        LUNE_IP_CPY(&nb->dst_addr, dst_addr);
        nb->state = NB_STATE_ALIVE;
        nb->queue_pkt_cnt = 0;
        nb->ref_cnt = 0;
        nb->ifp = ifp;

        if (0 != (err = htable_insert((void *)nb, s_nb_htable, 1))) {
            lune_mem_pool_free(s_nb_mem_pool, nb);
            return err;
        }

        timer_add_timer(&nb->tmr, s_nb_live_time);
        nb_first_hold(nb);
        return 0;
    }

    /* update dst_mac anyway */
    LUNE_MAC_CPY(nb->dst_mac, dst_mac);

    if (NB_STATE_REQ == nb->state) {
        nb->state = NB_STATE_ALIVE;

        lune_assert(NULL != nb->ipp);

        dequeue_pkt_cnt = 0;
        dlist_for_each_node_safe(pbuf, pbuf2, &nb->pbuf_list, node) {
            unsigned long long bytes;

            if (dequeue_pkt_cnt >= NB_DEQUEUE_MAX_PKT_NUM_ONCE) {
                timer_reuse_timer(&nb->tmr,
                    LUNE_TIMER_ONCE, LUNE_TIMER_RES_HIGH, (lune_timer_func_t)nb_dequeue, nb);
                timer_add_timer(&nb->tmr, NB_DEFAULT_DEQUEUE_INTVL);
                return 0;
            }

            bytes = PBUF_GET_PAYLOAD_LEN(pbuf) + PBUF_GET_HDR_LEN(pbuf);

            lune_assert(NULL != pbuf->macp);
            if (0 != (err = mac_output((mac_t *)pbuf->macp,
                nb->dst_mac, NB_GET_ETH_TYPE(nb), pbuf))) {
                lune_log(LUNE_INFO, "failed to send %d cached packets: %s",
                    nb->queue_pkt_cnt, ERR_GET_ERR_STR(err));
                /* reuse retrans field and default value */
                nb->retrans = NB_DEFAULT_DEQUEUE_RETRANS_TIMES;
                timer_reuse_timer(&nb->tmr,
                    LUNE_TIMER_ONCE, LUNE_TIMER_RES_HIGH, (lune_timer_func_t)nb_retrans, nb);
                timer_add_timer(&nb->tmr, NB_DEFAULT_DEQUEUE_RETRANS_INTVL);
                return 0;
            }

            nb->ipp->stats.pkt_out++;
            nb->ipp->stats.byte_out += bytes;

            dlist_del(&pbuf->node);
#ifdef LUNE_BUILD_DPDK
            if (!MAC_IS_DPDK(pbuf->macp) || !PBUF_IS_DPDK_PBUF(pbuf)) {
#endif
                mac_put((mac_t *)pbuf->macp);
                pbuf_free_pbuf(pbuf);
#ifdef LUNE_BUILD_DPDK
            } else {
                /* put mac after conditional check */
                mac_put((mac_t *)pbuf->macp);
                pbuf_dpdk_pbuf_put(pbuf);
            }
#endif

            nb->queue_pkt_cnt--;
            dequeue_pkt_cnt++;
        }

        timer_reuse_timer(&nb->tmr,
            LUNE_TIMER_ONCE, LUNE_TIMER_RES_HIGH, (lune_timer_func_t)nb_expire, nb);
        timer_add_timer(&nb->tmr, s_nb_live_time);
        return 0;
    }

    lune_assert(NB_STATE_ALIVE == nb->state);

    if (0 == nb->queue_pkt_cnt) {
        /* refresh expiry time if it is already in nb cache */
        timer_mod_timer(&nb->tmr, s_nb_live_time);
    } else {
        /* dequeue in progress */
    }

    return 0;
}

static int nb_htable_hash(neighbor_t *nb)
{
    return (LUNE_IP_GET_LE_INT(&nb->dst_addr) & NB_HTABLE_MASK);
}

static int nb_htable_compare(neighbor_t *nb1, neighbor_t *nb2)
{
    return (LUNE_IP_CMP(&nb1->dst_addr, &nb2->dst_addr)
        || nb1->ifp != nb2->ifp);
}

static void nb_htable_free(neighbor_t *nb)
{
    pbuf_t *pbuf, *pbuf2;

    if (LUNE_TIMER_IS_ADDED(nb->tmr)) {
        timer_del_timer(&nb->tmr);
    }

    if (NULL != nb->ipp) {
        ip_put(nb->ipp);
    }

    dlist_for_each_node_safe(pbuf, pbuf2, &nb->pbuf_list, node) {
        lune_assert(NULL != pbuf->macp);
        dlist_del(&pbuf->node);
#ifdef LUNE_BUILD_DPDK
        if (!MAC_IS_DPDK(pbuf->macp) || !PBUF_IS_DPDK_PBUF(pbuf)) {
#endif
            mac_put((mac_t *)pbuf->macp);
            pbuf_free_pbuf(pbuf);
#ifdef LUNE_BUILD_DPDK
        } else {
            /* put mac after conditional check */
            mac_put((mac_t *)pbuf->macp);
            pbuf_dpdk_pbuf_put(pbuf);
        }
#endif
    }

    lune_assert(1 == nb->ref_cnt);
    nb_put(nb);
}

int nb_local_init(void)
{
    if (NULL == (s_nb_mem_pool =
        lune_create_mem_pool("neighbor", sizeof(neighbor_t)))) {
        goto ERR_1;
    }

    if (NULL == (s_nb_htable = htable_create_table("neighbor hash table",
        (htable_hash_func_t)nb_htable_hash,
        (htable_compare_func_t)nb_htable_compare,
        (htable_free_func_t)nb_htable_free,
        offsetof(neighbor_t, node),
        NB_HTABLE_SIZE,
        0))) {
        goto ERR_2;
    }

    s_nb_live_time = NB_DEFAULT_LIVE_TIME;
    s_nb_retrans_times = NB_DEFAULT_REQ_RETRANS_TIMES;
    s_nb_retrans_intvl = NB_DEFAULT_REQ_RETRANS_INTVL   ;

    return 0;

ERR_2:
    (void)lune_delete_mem_pool(s_nb_mem_pool);
    s_nb_mem_pool = NULL;

ERR_1:
    return ERR_GET_LAST_ERR();
}

void nb_local_fini(void)
{
    lune_assert(!htable_delete_table(s_nb_htable));
    s_nb_htable = NULL;

    (void)lune_delete_mem_pool(s_nb_mem_pool);
    s_nb_mem_pool = NULL;
}

/*
    flush cache (if any) and resolve mac by launching a new request.
    paired with lune_get_resolved_mac to resolve mac of a specific ip
    (ipv4/ipv6) asynchronously
*/
int lune_resolve_mac(unsigned int ip_id, const lune_ip_addr_t *dst_addr)
{
    neighbor_t *nb;
    ip_t *ipp;

    if (LUNE_INVALID_ID == ip_id) {
        return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
    }

    if (NULL == (ipp = ip_get_ip_by_id(ip_id))) {
        return ERR_SET_ERR(LUNE_ERR_ID_NOT_FOUND);
    }

    if (LUNE_ID_MAC != ipp->lower_type) {
        return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
    }

    if (!!IP_IS_IPV6(ipp) != !!dst_addr->is_ipv6) {
        return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
    }

    if (NULL != (nb = nb_lookup(dst_addr, ipp->ifp))) {
        /* flush cache */
        nb_delete(nb);
    }

    /* send arp request and put packet on hold till response received */
    return nb_request_and_cache_pkt(dst_addr, ipp, (mac_t *)ipp->lower_entry, NULL);
}

int lune_get_resolved_mac(const lune_ip_addr_t *dst_addr, lune_mac_addr_t dst_mac, unsigned int net_if_id)
{
    neighbor_t *nb;
    void *ifp;

    if (NULL == dst_addr || NULL == dst_mac) {
        return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
    }

    ifp = net_if_get_net_if_by_id(net_if_id);
    if (NULL == (nb = nb_lookup(dst_addr, ifp))
        || NB_STATE_REQ == nb->state) {
        /* ERR_SET_ERR() unneeded */
        return -LUNE_ERR_NOT_EXIST;
    }

    LUNE_MAC_CPY(dst_mac, nb->dst_mac);
    return 0;
}
