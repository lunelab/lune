/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2024 Lune Reseau, Inc.
 */

#ifndef __PBUF_H_PRE__
#define __PBUF_H_PRE__

typedef struct _pbuf pbuf_t;

#endif

#ifndef __PBUF_H__
#define __PBUF_H__

#include "lune/assert.h"
#include "lune/atomic.h"
#include "lune/common.h"
#include "lune/err.h"
#include "lune/id.h"
#include "lune/list.h"
#include "lune/log.h"
#include "lune/mem.h"
#include "lune/os/linux.h"
#include "lune/tcp.h"

#ifdef LUNE_BUILD_DPDK
#include "drv/dpdk/net_if_dpdk.h"
#endif
#include "err/err.h"
#include "kernel/time.h"
#include "kernel/timer.h"

#define PBUF_IS_REF(pbuf)           \
    (lune_atomic32_get(&((pbuf_t *)(pbuf))->ref_cnt) >= 1)
#define PBUF_SET_UNREF(pbuf)        \
    do { lune_atomic32_set(&((pbuf_t *)(pbuf))->ref_cnt, -1); } while (0)

#define PBUF_GET_ETH_HDR(pbuf)      (((pbuf_t *)(pbuf))->ethh)
#define PBUF_SET_ETH_HDR(pbuf, hdr) do { (((pbuf_t *)(pbuf))->ethh) = (hdr); } while (0)

#define PBUF_GET_HDR_LEN(pbuf)      (((const pbuf_t *)(pbuf))->hdr_len)
#define PBUF_GET_PAYLOAD_LEN(pbuf)  (((const pbuf_t *)(pbuf))->payload_len)
#ifdef LUNE_BUILD_DPDK
#define PBUF_GET_PKT_LEN(pbuf)      (NULL != ((const pbuf_t *)(pbuf))->mbuf)    \
    ? ((const pbuf_t *)(pbuf))->mbuf->data_len : (PBUF_GET_HDR_LEN(pbuf) + PBUF_GET_PAYLOAD_LEN(pbuf))
#define PBUF_GET_HDR(pbuf)          ((NULL != ((pbuf_t *)(pbuf))->mbuf)         \
    ? (unsigned char *)((unsigned char *)(((pbuf_t *)(pbuf))->mbuf->buf_addr)   \
    + ((pbuf_t *)(pbuf))->mbuf->data_off)                                       \
    : ((pbuf_t *)(pbuf))->hdr)
#else
#define PBUF_GET_PKT_LEN(pbuf)      \
    PBUF_GET_HDR_LEN(pbuf) + PBUF_GET_PAYLOAD_LEN(pbuf)
#define PBUF_GET_HDR(pbuf)          (((pbuf_t *)(pbuf))->hdr)
#endif
/* PBUF_GET_PAYLOAD can only be used for non-dpdk pbuf */
#define PBUF_GET_PAYLOAD(pbuf)      (((pbuf_t *)(pbuf))->payload)

#define PBUF_UPDATE_JIFFIES(pbuf)   \
    do { ((pbuf_t *)(pbuf))->jiffies = TIMER_GET_CURRENT_JIFFIES(); } while (0)

typedef struct _pbuf_tcp {
    lune_tcp_hdr_t *hdr;
    unsigned int retrans_times;
    unsigned int data_len;
} pbuf_tcp_t;

/* packet buffer */
typedef struct _pbuf {
    dlist_node_t node;
#ifdef LUNE_BUILD_DPDK
    /* pbuf size is fixed for dpdk case, cache it on per-core-list */
    dlist_node_t node2;
#endif
    unsigned char *hdr;                 /* unused for dpdk pbuf */
    unsigned char *payload;             /* unused for dpdk pbuf */
    unsigned char *buf;                 /* unused for dpdk pbuf */
    unsigned short hdr_len;
    unsigned short payload_len;
    unsigned int buf_len;               /* unused for dpdk pbuf */
    unsigned long long jiffies;
    union {
        unsigned long long pkt_info;    /* combined for easy fetch */
        struct {
            unsigned short l2_len;
            unsigned short l3_len;
            unsigned short l4_len;
#define PBUF_FLAG_ON(pbuf, flag)        (((pbuf_t *)(pbuf))->flags & (flag))
#define PBUF_SET_FLAG(pbuf, flag)       \
    do { ((pbuf_t *)(pbuf))->flags |= (flag); } while (0)
#define PBUF_CLEAR_FLAG(pbuf, flag)     \
    do { ((pbuf_t *)(pbuf))->flags &= (~flag); } while (0)
#define PBUF_FLAG_L3_IPV4               0x0001
#define PBUF_IS_L3_IPV4(pbuf)           PBUF_FLAG_ON(pbuf, PBUF_FLAG_L3_IPV4)
#define PBUF_SET_L3_IPV4(pbuf)          PBUF_SET_FLAG(pbuf, PBUF_FLAG_L3_IPV4)
#define PBUF_SET_L3_IPV6(pbuf)          PBUF_CLEAR_FLAG(pbuf, PBUF_FLAG_L3_IPV4)
#define PBUF_MASK_L4_TYPE               0x000e
#define PBUF_L4_TYPE_OTHERS             0x0000
#define PBUF_L4_TYPE_TCP                0x0002
#define PBUF_L4_TYPE_UDP                0x0004
#define PBUF_L4_TYPE_ICMP               0x0006
#define PBUF_L4_TYPE_IGMP               0x0008
#define PBUF_GET_L4_TYPE(pbuf)          ((pbuf)->flags & PBUF_MASK_L4_TYPE)
#define PBUF_SET_L4_TYPE(pbuf, type)    \
    do { (pbuf)->flags =                \
        ((pbuf)->flags & (~PBUF_MASK_L4_TYPE)) | (type); } while (0)
#define PBUF_SET_L4_TYPE_TCP(pbuf)      \
    PBUF_SET_L4_TYPE(pbuf, PBUF_L4_TYPE_TCP)
#define PBUF_SET_L4_TYPE_UDP(pbuf)      \
    PBUF_SET_L4_TYPE(pbuf, PBUF_L4_TYPE_UDP)
#define PBUF_SET_L4_TYPE_ICMP(pbuf)     \
    PBUF_SET_L4_TYPE(pbuf, PBUF_L4_TYPE_ICMP)
#define PBUF_SET_L4_TYPE_IGMP(pbuf)     \
    PBUF_SET_L4_TYPE(pbuf, PBUF_L4_TYPE_IGMP)
#define PBUF_FLAG_TX                    0x0010
#define PBUF_IS_TX(pbuf)                PBUF_FLAG_ON(pbuf, PBUF_FLAG_TX)
#define PBUF_SET_TX(pbuf)               PBUF_SET_FLAG(pbuf, PBUF_FLAG_TX)
#define PBUF_SET_RX(pbuf)               PBUF_CLEAR_FLAG(pbuf, PBUF_FLAG_TX)
            unsigned short flags;
        };
    };
    union {
        pbuf_tcp_t tcp;
    };
    /* used for optimization of tcp data packet transmission */
    lune_atomic32_t ref_cnt;
    /* store mac instance needed by arp */
    void *macp;
    unsigned char *ethh;
#ifdef LUNE_BUILD_DPDK
#define PBUF_IS_DPDK_PBUF(pbuf)         (NULL != ((const pbuf_t *)(pbuf))->mbuf)
    struct rte_mbuf *mbuf;
#endif
} pbuf_t;

#define PBUF_MAX_RSVD_HDR_LEN           (128)

static inline unsigned char *pbuf_move_up(pbuf_t *pbuf, unsigned short len)
{
#ifdef LUNE_DEBUG
    lune_assert(len > 0);
#ifdef LUNE_BUILD_DPDK
    lune_assert(NULL == pbuf->mbuf);
#endif
#endif

    if (unlikely(len > pbuf->payload_len)) {
        /* exceed the end of data */
        lune_log(LUNE_WARN, "internal error: length %d to move up more than pbuf "
            "remaining length %d", len, pbuf->payload_len);
        ERR_SET_ERR(LUNE_ERR_PBUF_INTERNAL);
        return NULL;
    }

    pbuf->hdr = pbuf->payload;
    pbuf->hdr_len = len;
    pbuf->payload += len;
    pbuf->payload_len -= len;

    return pbuf->hdr;
}

static inline unsigned char *pbuf_move_down(pbuf_t *pbuf, unsigned short len)
{
#ifdef LUNE_DEBUG
    lune_assert(len > 0);
#endif

#ifdef LUNE_BUILD_DPDK
    if (NULL != pbuf->mbuf) {
        unsigned char *buf;
        /* tcp pbuf */
        if (unlikely(NULL == (buf = (unsigned char *)rte_pktmbuf_prepend(pbuf->mbuf, len)))) {
            lune_log(LUNE_WARN, "internal error: length %d to move down more than pbuf "
                "remaining length %d", len, pbuf->buf_len - pbuf->payload_len);
            ERR_SET_ERR(LUNE_ERR_PBUF_INTERNAL);
            return NULL;
        }

        pbuf->payload_len += pbuf->hdr_len;
        pbuf->hdr_len = len;

        return buf;
    }
#endif

    if (unlikely(len + pbuf->payload_len > pbuf->buf_len)) {
        lune_log(LUNE_WARN, "internal error: length %d to move down more than pbuf "
            "remaining length %d", len, pbuf->buf_len - pbuf->payload_len);
        ERR_SET_ERR(LUNE_ERR_PBUF_INTERNAL);
        return NULL;
    }

    pbuf->payload = pbuf->hdr;
    pbuf->payload_len += pbuf->hdr_len;
    pbuf->hdr -= len;
    pbuf->hdr_len = len;

    return pbuf->hdr;
}

#ifdef LUNE_BUILD_DPDK
extern __thread dlist_head_t g_pbuf_dpdk_pbuf_list;

static inline void pbuf_dpdk_cache_send_pbuf(pbuf_t *pbuf)
{
    dlist_add_head(&pbuf->node2, &g_pbuf_dpdk_pbuf_list);
}

static pbuf_t *pbuf_dpdk_get_send_pbuf(void)
{
    pbuf_t *pbuf;

    if (dlist_is_empty(&g_pbuf_dpdk_pbuf_list)) {
        return NULL;
    }

    pbuf = dlist_first(&g_pbuf_dpdk_pbuf_list, pbuf_t, node2);
    dlist_del(&pbuf->node2);

    return pbuf;
}
#endif

static inline void pbuf_hold(pbuf_t *pbuf)
{
    lune_assert(0 <= lune_atomic32_get(&pbuf->ref_cnt));
    lune_atomic32_inc(&pbuf->ref_cnt);
}

static inline void pbuf_put(pbuf_t *pbuf)
{
#if defined(LUNE_BUILD_DPDK) && defined(LUNE_DEBUG)
    lune_assert(NULL == pbuf->mbuf);
#endif
    lune_assert(0 < lune_atomic32_get(&pbuf->ref_cnt));
    if (lune_atomic32_dec_is_zero(&pbuf->ref_cnt)) {
        lune_free_mt(pbuf);
    }
}

static inline void pbuf_put_last(pbuf_t *pbuf)
{
    lune_assert(lune_atomic32_dec_is_zero(&pbuf->ref_cnt));
    lune_free_mt(pbuf);
}

#ifdef LUNE_BUILD_DPDK
pbuf_t *pbuf_dpdk_alloc_send_pbuf(unsigned short len);
void pbuf_dpdk_free_send_pbuf(pbuf_t *pbuf);

#define pbuf_dpdk_pbuf_hold(pbuf)       pbuf_hold(pbuf)
static inline void pbuf_dpdk_pbuf_put(pbuf_t *pbuf)
{
    if (lune_atomic32_dec_is_zero(&pbuf->ref_cnt)) {
        pbuf_dpdk_free_send_pbuf(pbuf);
    }
}
#endif

static inline int pbuf_is_last_ref(pbuf_t *pbuf)
{
    return (1 == lune_atomic32_get(&pbuf->ref_cnt));
}

static inline void pbuf_init_recv_pbuf(pbuf_t *pbuf,
    unsigned char *buf, unsigned short len)
{
    dlist_init_node(&pbuf->node);
    pbuf->buf = (unsigned char *)buf;
    pbuf->buf_len = len;
    pbuf->hdr = pbuf->payload = pbuf->buf;
    pbuf->hdr_len = 0;
    pbuf->payload_len = len;
    pbuf->jiffies = TIMER_GET_CURRENT_JIFFIES();
    pbuf->pkt_info = 0;
#ifdef LUNE_BUILD_DPDK
    pbuf->mbuf = NULL;
#endif
}

/*
    pbuf_init_send_pbuf() supports both dpdk pbuf and non-dpdk pbuf initialization
    in case of dpdk pbuf, a pbuf with dpdk mbuf will be created and released by dpdk
    driver after transmission. caller MUST determine the way of initialization, i.e.,
    whether the packet needs fragmentation. A fragmented packet cannot use dpdk pbuf.
*/
#ifdef LUNE_BUILD_DPDK
#define pbuf_init_send_pbuf(pbuf, buf, len, rsvd_hdr_len, is_dpdk)  \
    __pbuf_init_send_pbuf(pbuf, buf, len, rsvd_hdr_len, is_dpdk)

static inline void __pbuf_init_send_pbuf(pbuf_t *pbuf,
    unsigned char *buf, unsigned short len, unsigned short rsvd_hdr_len, unsigned int is_dpdk)
#else
#define pbuf_init_send_pbuf(pbuf, buf, len, rsvd_hdr_len, is_dpdk)  \
    __pbuf_init_send_pbuf(pbuf, buf, len, rsvd_hdr_len)

static inline void __pbuf_init_send_pbuf(pbuf_t *pbuf,
    unsigned char *buf, unsigned short len, unsigned short rsvd_hdr_len)
#endif
{
    dlist_init_node(&pbuf->node);
    pbuf->buf_len = len + rsvd_hdr_len;
    pbuf->hdr_len = 0;
    pbuf->payload_len = len;
    pbuf->jiffies = TIMER_GET_CURRENT_JIFFIES();
    pbuf->pkt_info = 0;
    PBUF_SET_TX(pbuf);
    pbuf->macp = NULL;
    pbuf->ethh = NULL;
    PBUF_SET_UNREF(pbuf);
#ifdef LUNE_BUILD_DPDK
    if (is_dpdk) {
        if (NULL != (pbuf->mbuf = rte_pktmbuf_alloc(g_net_if_dpdk_send_mbuf_pool))) {
            pbuf->mbuf->data_len = len;
            return;
        }

        /* fall back to non-dpdk initialization */
    }
    pbuf->mbuf = NULL;
#endif
    pbuf->buf = (unsigned char *)buf;
    pbuf->hdr = pbuf->payload = pbuf->buf + rsvd_hdr_len;
}

static inline pbuf_t *pbuf_alloc_recv_pbuf(unsigned short len, unsigned short rsvd_hdr_len)
{
    pbuf_t *pbuf;
    unsigned int hdr_len = ALIGN_8B(rsvd_hdr_len);

    if (NULL == (pbuf = (pbuf_t *)lune_malloc_mt(sizeof(pbuf_t) + hdr_len + len))) {
        ERR_SET_ERR(LUNE_ERR_NO_MEM);
        return NULL;
    }

    dlist_init_node(&pbuf->node);
    pbuf->buf = ((unsigned char *)pbuf) + sizeof(pbuf_t);
    pbuf->buf_len = hdr_len + len;
    pbuf->hdr = pbuf->payload = ((unsigned char *)pbuf) + sizeof(pbuf_t) + hdr_len;
    pbuf->hdr_len = 0;
    pbuf->payload_len = len;
    pbuf->jiffies = TIMER_GET_CURRENT_JIFFIES();
    pbuf->pkt_info = 0;
    pbuf->macp = NULL;
    pbuf->ethh = NULL;
#ifdef LUNE_BUILD_DPDK
    pbuf->mbuf = NULL;
#endif
    lune_atomic32_set(&pbuf->ref_cnt, 0);

    return pbuf;
}

static inline pbuf_t *pbuf_alloc_send_pbuf(unsigned short len, unsigned short rsvd_hdr_len)
{
    pbuf_t *pbuf;
    unsigned int hdr_len = ALIGN_8B(rsvd_hdr_len);

    if (NULL == (pbuf = (pbuf_t *)lune_malloc_mt(sizeof(pbuf_t) + hdr_len + len))) {
        ERR_SET_ERR(LUNE_ERR_NO_MEM);
        return NULL;
    }

    dlist_init_node(&pbuf->node);
    pbuf->buf = ((unsigned char *)pbuf) + sizeof(pbuf_t);
    pbuf->buf_len = hdr_len + len;
    pbuf->hdr = pbuf->payload = ((unsigned char *)pbuf) + sizeof(pbuf_t) + hdr_len;
    pbuf->hdr_len = 0;
    pbuf->payload_len = len;
    pbuf->jiffies = TIMER_GET_CURRENT_JIFFIES();
    pbuf->pkt_info = 0;
    PBUF_SET_TX(pbuf);
    pbuf->macp = NULL;
    pbuf->ethh = NULL;
#ifdef LUNE_BUILD_DPDK
    pbuf->mbuf = NULL;
#endif
    lune_atomic32_set(&pbuf->ref_cnt, 0);

    return pbuf;
}

#ifdef LUNE_BUILD_DPDK
static inline pbuf_t *pbuf_dpdk_spawn_send_pbuf(pbuf_t *pbuf)
{
    pbuf_t *pbuf_spawn;

#ifdef LUNE_DEBUG
    lune_assert(NULL == pbuf->macp);
    lune_assert(NULL != pbuf->mbuf);
#endif

    if (NULL == (pbuf_spawn = pbuf_dpdk_get_send_pbuf())) {
        if (NULL == (pbuf_spawn = (pbuf_t *)lune_malloc_mt(sizeof(pbuf_t)))) {
            ERR_SET_ERR(LUNE_ERR_NO_MEM);
            return NULL;
        }
    } else {
        /* cached pbuf available */
    }

    dlist_init_node(&pbuf_spawn->node);
    pbuf_spawn->hdr_len = pbuf->hdr_len;
    pbuf_spawn->payload_len = pbuf->payload_len;
    pbuf_spawn->jiffies = pbuf->jiffies;
    pbuf_spawn->pkt_info = pbuf->pkt_info;
    pbuf_spawn->macp = NULL;
    pbuf_spawn->ethh = NULL;
    /* mbuf is passed to new pbuf */
    pbuf_spawn->mbuf = pbuf->mbuf;
    pbuf->mbuf = NULL;
    lune_atomic32_set(&pbuf_spawn->ref_cnt, 0);

    return pbuf_spawn;
}
#endif

static inline pbuf_t *pbuf_dup_pbuf(const pbuf_t *pbuf)
{
    pbuf_t *pbuf_dup;

    lune_assert(NULL != pbuf);

    if (NULL == (pbuf_dup = (pbuf_t *)lune_malloc_mt(sizeof(pbuf_t) + pbuf->buf_len))) {
        ERR_SET_ERR(LUNE_ERR_NO_MEM);
        return NULL;
    }

    dlist_init_node(&pbuf_dup->node);
    pbuf_dup->buf = ((unsigned char *)pbuf_dup) + sizeof(pbuf_t);
    pbuf_dup->buf_len = pbuf->buf_len;
    pbuf_dup->payload = ((unsigned char *)pbuf_dup) + sizeof(pbuf_t)
        + ((unsigned char *)pbuf->payload - (unsigned char *)pbuf->buf);
    pbuf_dup->payload_len = pbuf->payload_len;
    pbuf_dup->hdr = ((unsigned char *)pbuf_dup->payload) - pbuf->hdr_len;
    pbuf_dup->hdr_len = pbuf->hdr_len;
    pbuf_dup->jiffies = TIMER_GET_CURRENT_JIFFIES();
    pbuf_dup->pkt_info = pbuf->pkt_info;
    if (PBUF_L4_TYPE_TCP == PBUF_GET_L4_TYPE(pbuf)) {
        pbuf_dup->tcp.hdr = (lune_tcp_hdr_t *)(pbuf_dup->hdr
            + ((unsigned char *)pbuf->tcp.hdr - pbuf->hdr));
        pbuf_dup->tcp.retrans_times = pbuf->tcp.retrans_times;
        pbuf_dup->tcp.data_len = pbuf->tcp.data_len;
    }
    pbuf_dup->macp = NULL;
    pbuf_dup->ethh = NULL;
#ifdef LUNE_BUILD_DPDK
    pbuf_dup->mbuf = NULL;
#endif
    lune_atomic32_set(&pbuf_dup->ref_cnt, 0);

    /* only duplicate payload and current header */
    if (pbuf_dup->hdr_len > 0) {
        memcpy(pbuf_dup->hdr, pbuf->hdr, pbuf->hdr_len);
    }
    memcpy(pbuf_dup->payload, pbuf->payload, pbuf->payload_len);

    return pbuf_dup;
}

/*
    caller MUST ensure pbuf is not null
*/
static inline void pbuf_free_pbuf(pbuf_t *pbuf)
{
    lune_free_mt(pbuf);
}

static inline void pbuf_truncate_pbuf(pbuf_t *pbuf, unsigned short len)
{
    lune_assert((pbuf->buf + pbuf->buf_len) == (pbuf->payload + pbuf->payload_len));

    pbuf->payload_len = len;
}

static inline void pbuf_reset_pbuf(pbuf_t *pbuf, unsigned char *hdr, unsigned char *payload)
{
    pbuf->payload_len = pbuf->buf + pbuf->buf_len - payload;
    pbuf->payload = payload;
    pbuf->hdr_len = payload - hdr;
    pbuf->hdr = hdr;
}

static inline void pbuf_rebase_pbuf(pbuf_t *pbuf, unsigned short len)
{
    pbuf->hdr = pbuf->payload = pbuf->buf + pbuf->buf_len - len;
    pbuf->payload_len = len;
    pbuf->hdr_len = 0;
}

static inline void pbuf_update_payload_len(pbuf_t *pbuf, unsigned short len)
{
    pbuf->payload_len = len;
}

unsigned short pbuf_get_max_hdr_len(lune_id_type_en type, void *entry);

int pbuf_local_init(void);
void pbuf_local_fini(void);

#endif