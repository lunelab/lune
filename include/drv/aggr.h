/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2024 Lune Reseau, Inc.
 */

#ifndef __AGGR_H_PRE__
#define __AGGR_H_PRE__

typedef struct _aggr_net_if aggr_net_if_t;

#endif

#ifndef __AGGR_H__
#define __AGGR_H__

#include "lune/atomic.h"
#include "lune/net_if.h"
#include "lune/os/linux.h"

#include "drv/net_if.h"
#include "lib/ringbuf.h"
#include "net/pbuf.h"

#define AGGR_NET_IF_MIN_CHAN_PER_AGGR_NUM           (1)
#define AGGR_NET_IF_MAX_CHAN_PER_AGGR_NUM           (16)
/* the following macro used only for dpdk multi-queue */
#define AGGR_NET_IF_MAX_AGGR_PER_NET_IF_NUM         (8)

#define AGGR_CHAN_RX_RB_PKT_NUM                     (8192)
#define AGGR_CHAN_RX_RB_PKT_SIZE                    (256)

#define AGGR_CHAN_GET_RX_LEN(frm)                   (((aggr_chan_rx_hdr_t *)frm)->len)
#define AGGR_CHAN_GET_RX_PTR(frm)                   (((aggr_chan_rx_hdr_t *)frm)->buf)

#define AGGR_CHAN_BUILD_RX_PTR_HDR(frm, l, p)       \
    do {                                            \
        ((aggr_chan_rx_hdr_t *)frm)->type = AGGR_CHAN_RX_PTR;           \
        ((aggr_chan_rx_hdr_t *)frm)->len = (l);     \
        g_aggr_curr_ifp->drv->recv_fwd_pkt(g_aggr_curr_ifp->net_if_data,\
            &((aggr_chan_rx_hdr_t *)frm)->data);    \
        ((aggr_chan_rx_hdr_t *)frm)->buf = (unsigned char *)(p);        \
    } while (0)

#define AGGR_CHAN_BUILD_RX_PKT_HDR(frm, l, p)       \
    do {                                            \
        ((aggr_chan_rx_hdr_t *)frm)->type = AGGR_CHAN_RX_PKT;           \
        ((aggr_chan_rx_hdr_t *)frm)->len = (l);     \
        ((aggr_chan_rx_hdr_t *)frm)->buf = NULL;    \
        memcpy((unsigned char *)frm                 \
            + sizeof(aggr_chan_rx_hdr_t), (p), (l));\
    } while (0)

#pragma pack(8)
typedef struct _aggr_chan_rx_hdr {
#define AGGR_CHAN_RX_PTR                            (0)
#define AGGR_CHAN_RX_PKT                            (1)
    unsigned int type;
    unsigned int len;
    void *data;         /* used for AGGR_CHAN_RX_PTR type only */
    unsigned char *buf;
} aggr_chan_rx_hdr_t;
#pragma pack()

typedef struct _aggr_chan {
    char name[LUNE_MAX_SHORT_NAME_BUF_LEN];
    aggr_net_if_t *aip;
    net_if_t *ifp;      /* pointer to net_if struct */
    void *rx_rb;        /* pointer to rx ring buffer */
    void *tx_mq;        /* pointer to tx message queue */
    unsigned char *curr_frm;
    unsigned int idx;
} aggr_chan_t;

typedef struct _aggr_net_if {
    dlist_node_t node;  /* hash table node */
    lune_atomic32_t ref_cnt;
    unsigned int tx_task_id;
    union {
#define AGGR_NET_IF_MAC_GET_START_MAC(ai)           (((aggr_net_if_t *)ai)->mac.start_mac)
#define AGGR_NET_IF_MAC_GET_END_MAC(ai)             (((aggr_net_if_t *)ai)->mac.end_mac)
#define AGGR_NET_IF_MAC_GET_STEP(ai)                (((aggr_net_if_t *)ai)->mac.step)
        struct {
            unsigned long long start_mac;
            unsigned long long end_mac;
            unsigned int step;
        } mac;
#define AGGR_NET_IF_IP_GET_START_IPV4(ai)           (((aggr_net_if_t *)ai)->ip.start_ip.ipv4)
#define AGGR_NET_IF_IP_GET_END_IPV4(ai)             (((aggr_net_if_t *)ai)->ip.end_ip.ipv4)
#define AGGR_NET_IF_IP_GET_START_IPV6(ai)           (((aggr_net_if_t *)ai)->ip.start_ip.ipv6)
#define AGGR_NET_IF_IP_GET_END_IPV6(ai)             (((aggr_net_if_t *)ai)->ip.end_ip.ipv6)
#define AGGR_NET_IF_IP_GET_STEP(ai)                 (((aggr_net_if_t *)ai)->ip.step)
        struct {
            lune_ip_addr_t start_ip;
            lune_ip_addr_t end_ip;
            unsigned int step;
        } ip;
#define AGGR_NET_IF_CUST_GET_DIST_FUNC(ai)          (((aggr_net_if_t *)ai)->cust.dist)
#define AGGR_NET_IF_CUST_GET_DIST_DATA(ai)          (((aggr_net_if_t *)ai)->cust.data)
        struct {
            lune_net_if_aggr_recv_dist_func_t dist;
            void *data;
        } cust;
    };
#define AGGR_NET_IF_GET_TYPE(ai)                    (((aggr_net_if_t *)ai)->type)
    lune_net_if_aggr_type_en type;
#define AGGR_NET_IF_GET_TOTAL_CHAN_NUM(ai)          (((aggr_net_if_t *)ai)->total_chan_num)
    unsigned int total_chan_num;
    unsigned int curr_chan_num;
    lune_atomic32_t curr_active_chan_num;
    aggr_chan_t *chan_array[AGGR_NET_IF_MAX_CHAN_PER_AGGR_NUM];
    net_if_t *ifp;      /* pointer to net_if struct */
    char name[LUNE_MAX_SHORT_NAME_BUF_LEN];
    pthread_spinlock_t lock;
#define AGGR_NET_IF_FLAG_AGGR_SEND                  0x00000001
#define AGGR_NET_IF_IS_AGGR_SEND(ai)                (((aggr_net_if_t *)ai)->flags & AGGR_NET_IF_FLAG_AGGR_SEND)
#define AGGR_NET_IF_SET_AGGR_SEND(ai)               \
    do { ((aggr_net_if_t *)ai)->flags =             \
        (((aggr_net_if_t *)ai)->flags | (AGGR_NET_IF_FLAG_AGGR_SEND)); } while (0)
#define AGGR_NET_IF_CLEAR_AGGR_SEND(ai)             \
    do { ((aggr_net_if_t *)ai)->flags =             \
        (((aggr_net_if_t *)ai)->flags & (~AGGR_NET_IF_FLAG_AGGR_SEND)); } while (0)
#define AGGR_NET_IF_FLAG_REFCNT_AVAIL               0x00000002
#define AGGR_NET_IF_IS_REFCNT_AVAIL(ai)             (((aggr_net_if_t *)ai)->flags & AGGR_NET_IF_FLAG_REFCNT_AVAIL)
#define AGGR_NET_IF_SET_REFCNT_AVAIL(ai)            \
    do { ((aggr_net_if_t *)ai)->flags =             \
        (((aggr_net_if_t *)ai)->flags | (AGGR_NET_IF_FLAG_REFCNT_AVAIL)); } while (0)
#define AGGR_NET_IF_SET_REFCNT_UNAVAIL(ai)          \
    do { ((aggr_net_if_t *)ai)->flags =             \
        (((aggr_net_if_t *)ai)->flags & (~AGGR_NET_IF_FLAG_REFCNT_AVAIL)); } while (0)
    unsigned int flags;
    lune_atomic32_t tx_pkt_cnt;
} aggr_net_if_t;

#define AGGR_SET_CURR_AGGR_NET_IF(ifp)              \
    do { g_aggr_curr_ifp = (net_if_t *)(ifp); } while (0)
#define AGGR_CLEAR_CURR_AGGR_NET_IF()               AGGR_SET_CURR_AGGR_NET_IF(NULL)
extern __thread net_if_t *g_aggr_curr_ifp;

static inline int aggr_chan_recv(void *acp, const unsigned char **pbuf, unsigned int *plen)
{
    aggr_chan_rx_hdr_t *acrh;
    unsigned int frm_len;
    aggr_chan_t *ac = (aggr_chan_t *)acp;

#ifdef LUNE_DEBUG
    lune_assert(NULL != ac->rx_rb);
#endif

    if (ringbuf_get_read_frm(ac->rx_rb, (unsigned char **)&acrh, &frm_len)) {
        /* ERR_SET_ERR() unneeded */
        return -LUNE_ERR_NET_IF_NO_PKT;
    }

    switch (acrh->type) {
    case AGGR_CHAN_RX_PKT:
        *pbuf = (unsigned char *)acrh + sizeof(aggr_chan_rx_hdr_t);
        break;
    case AGGR_CHAN_RX_PTR:
        *pbuf = acrh->buf;
        break;
    default:
        lune_assert(0);
        ringbuf_read_frm_done(((aggr_chan_t *)acp)->rx_rb, (unsigned char *)acrh);
        return ERR_SET_ERR(LUNE_ERR_NET_IF_INTERNAL);
    }

    *plen = acrh->len;
    ac->curr_frm = (unsigned char *)acrh;

    return 0;
}

void aggr_net_if_update_tcp_stats(net_if_t *ifp);

int aggr_init(void);
void aggr_fini(void);

void *aggr_add_net_if(const char *name, const lune_net_if_aggr_conf_t *conf, net_if_t *ifp);
int aggr_del_net_if(void *p);

int aggr_enable_net_if(void *p);
int aggr_disable_net_if(void *p);

void *aggr_add_chan(const char *name, net_if_t *ifp);
int aggr_del_chan(void *p);

void aggr_enable_chan(void *p);
void aggr_disable_chan(void *p);

int aggr_is_net_if_ready(void *ai);

int aggr_chan_send(void *acp, const unsigned char *buf, unsigned int len, pbuf_t *pbuf);
void aggr_chan_recv_done(void *acp);
void aggr_chan_recv_pkts_done(void *acp, unsigned char *frm);
net_if_t *aggr_chan_get_aggr_ifp(void *acp);
unsigned int aggr_chan_get_id(void *acp);
unsigned int aggr_chan_get_aggr_chan_num(void *acp);

int aggr_net_if_recv(void *ai, unsigned char *buf, unsigned int len);
void *aggr_net_if_get_chan_data(void *ai, unsigned int idx);

#endif