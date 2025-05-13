/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2024 Lune Reseau, Inc.
 */

#ifndef __NET_IF_H__
#define __NET_IF_H__

#include "lune/list.h"
#include "lune/mem.h"
#include "lune/net_if.h"
#include "lune/socket.h"
#include "lune/time.h"

#include "kernel/timer.h"
#include "net/pbuf.h"
#include "utils/cap.h"

#define NET_IF_GET_TYPE(ifp)                    (((net_if_t *)ifp)->type)
#define NET_IF_GET_DATA(ifp)                    (((net_if_t *)ifp)->net_if_data)
#define NET_IF_GET_ID(ifp)                      (((net_if_t *)ifp)->id)

#define NET_IF_OPT_HW_RX_CSUM_IPV4_FLAG         (1 << 0)
#define NET_IF_OPT_IS_HW_RX_CSUM_IPV4(flags)    ((flags) & NET_IF_OPT_HW_RX_CSUM_IPV4_FLAG)
#define NET_IF_OPT_SET_HW_RX_CSUM_IPV4(flags)   \
    do { (flags) |= NET_IF_OPT_HW_RX_CSUM_IPV4_FLAG; } while (0)
#define NET_IF_OPT_HW_RX_CSUM_TCP_FLAG          (1 << 1)
#define NET_IF_OPT_IS_HW_RX_CSUM_TCP(flags)     ((flags) & NET_IF_OPT_HW_RX_CSUM_TCP_FLAG)
#define NET_IF_OPT_SET_HW_RX_CSUM_TCP(flags)    \
    do { (flags) |= NET_IF_OPT_HW_RX_CSUM_TCP_FLAG; } while (0)
#define NET_IF_OPT_HW_RX_CSUM_UDP_FLAG          (1 << 2)
#define NET_IF_OPT_IS_HW_RX_CSUM_UDP(flags)     ((flags) & NET_IF_OPT_HW_RX_CSUM_UDP_FLAG)
#define NET_IF_OPT_SET_HW_RX_CSUM_UDP(flags)    \
    do { (flags) |= NET_IF_OPT_HW_RX_CSUM_UDP_FLAG; } while (0)
#define NET_IF_OPT_HW_TX_CSUM_IPV4_FLAG         (1 << 3)
#define NET_IF_OPT_IS_HW_TX_CSUM_IPV4(flags)    ((flags) & NET_IF_OPT_HW_TX_CSUM_IPV4_FLAG)
#define NET_IF_OPT_SET_HW_TX_CSUM_IPV4(flags)   \
    do { (flags) |= NET_IF_OPT_HW_TX_CSUM_IPV4_FLAG; } while (0)
#define NET_IF_OPT_HW_TX_CSUM_TCP_FLAG          (1 << 4)
#define NET_IF_OPT_IS_HW_TX_CSUM_TCP(flags)     ((flags) & NET_IF_OPT_HW_TX_CSUM_TCP_FLAG)
#define NET_IF_OPT_SET_HW_TX_CSUM_TCP(flags)    \
    do { (flags) |= NET_IF_OPT_HW_TX_CSUM_TCP_FLAG; } while (0)
#define NET_IF_OPT_HW_TX_CSUM_UDP_FLAG          (1 << 5)
#define NET_IF_OPT_IS_HW_TX_CSUM_UDP(flags)     ((flags) & NET_IF_OPT_HW_TX_CSUM_UDP_FLAG)
#define NET_IF_OPT_SET_HW_TX_CSUM_UDP(flags)    \
    do { (flags) |= NET_IF_OPT_HW_TX_CSUM_UDP_FLAG; } while (0)

typedef enum _net_if_opt {
    /* get options */
    NET_IF_OPT_GET_MTU = LUNE_NET_IF_OPT_GET_MTU,
    NET_IF_OPT_GET_STATS = LUNE_NET_IF_OPT_GET_STATS,
    NET_IF_OPT_GET_CHAN_ID = LUNE_NET_IF_OPT_GET_CHAN_ID,
    /* set options */
    NET_IF_OPT_SET_MTU = LUNE_NET_IF_OPT_SET_MTU,
    NET_IF_OPT_PCAP_START = LUNE_NET_IF_OPT_PCAP_START,
    NET_IF_OPT_PCAP_STOP = LUNE_NET_IF_OPT_PCAP_STOP,
    NET_IF_OPT_DPDK_QUEUE_SET_DISTRIB = LUNE_NET_IF_OPT_DPDK_QUEUE_SET_DISTRIB,
    NET_IF_OPT_DPDK_QUEUE_CLEAR_DISTRIB = LUNE_NET_IF_OPT_DPDK_QUEUE_CLEAR_DISTRIB,
    /* get options, internal only */
    NET_IF_OPT_GET_HW_CSUM = 512,
    NET_IF_OPT_GET_MAX_DATA_RATE,
    NET_IF_OPT_GET_PORT_ID,         /* used by dpdk (queue) interface only */
    NET_IF_OPT_IS_RECV_REFCNT_AVAIL,
    NET_IF_OPT_GET_PEER_NET_IF,     /* used by virtual interface only */
    NET_IF_OPT_GET_CONN_TYPE,       /* used by virtual interface only */
    NET_IF_OPT_GET_MAC,
    NET_IF_OPT_GET_IPV4,
    NET_IF_OPT_GET_MASK,
    NET_IF_OPT_GET_GW,
    /* set options, internal only */
    NET_IF_OPT_DISABLE_HW_CSUM = 768,
    NET_IF_OPT_CONNECT_LOCAL,       /* used by virtual interface only */
    NET_IF_OPT_DISCONNECT_LOCAL,    /* used by virtual interface only */
    NET_IF_OPT_CONNECT_REMOTE,      /* used by virtual interface only */
    NET_IF_OPT_DISCONNECT_REMOTE,   /* used by virtual interface only */
    NET_IF_OPT_MAX = 1024,
} net_if_opt_en;

/* net_if_conn_type_en dedicated for virtual interface */
typedef enum _net_if_conn_type {
    NET_IF_CONN_TYPE_NONE = 0,
    NET_IF_CONN_TYPE_LOCAL,
    NET_IF_CONN_TYPE_REMOTE_ACTIVE,
    NET_IF_CONN_TYPE_REMOTE_PASSIVE,
} net_if_conn_type_en;

typedef struct _net_if_peer_net_if {
    unsigned int id;                /* peer interface id */
    unsigned int core_id;           /* peer core id */
} net_if_peer_net_if_t;

typedef struct _net_if_send_pkt {
    const unsigned char *buf;
    unsigned int len;
} net_if_send_pkt_t;

static_assert(sizeof(lune_socket_send_pkt_t) == sizeof(net_if_send_pkt_t),
    "send packet type unmatche");

typedef struct _net_if net_if_t;

typedef int (*net_if_add_net_if_func_t)(net_if_t *, const char *, const void *, unsigned int, void **);
typedef int (*net_if_del_net_if_func_t)(void *);
typedef int (*net_if_is_up_func_t)(void *);
typedef int (*net_if_set_up_func_t)(void *);
typedef int (*net_if_set_down_func_t)(void *);
typedef int (*net_if_send_func_t)(void *, const unsigned char *, unsigned int);
typedef int (*net_if_send_pkts_func_t)(void *, const net_if_send_pkt_t *, unsigned int);
typedef int (*net_if_recv_func_t)(void *, unsigned char **, unsigned int *);
typedef int (*net_if_recv_pkts_func_t)(void *);
typedef void (*net_if_recv_done_func_t)(void *);
typedef void (*net_if_recv_fwd_pkt_func_t)(void *, void **);
typedef void (*net_if_recv_free_pkt_func_t)(void *, unsigned char *, void *);
typedef int (*net_if_get_opt_func_t)(void *, net_if_opt_en, unsigned char *, unsigned int);
typedef int (*net_if_set_opt_func_t)(void *, net_if_opt_en, const unsigned char *, unsigned int);

typedef struct _net_if_drv {
    lune_net_if_type_en type;
    const char *name;
    /* add_net_if() must not be NULL and mtu must be set within the call */
    net_if_add_net_if_func_t add_net_if;
    net_if_del_net_if_func_t del_net_if;
    net_if_is_up_func_t is_up;
    /* set_up() must not be NULL if is_up not NULL */
    net_if_set_up_func_t set_up;
    net_if_set_down_func_t set_down;
    /* send() must not be NULL */
    net_if_send_func_t send;
    net_if_send_pkts_func_t send_pkts;
    /* either recv() or recv_pkts() must not be NULL */
    net_if_recv_func_t recv;
    net_if_recv_pkts_func_t recv_pkts;
    /* recv_done() must not be NULL */
    net_if_recv_done_func_t recv_done;
    /*
        recv_fwd_pkt() and recv_free_pkt() are a pair for aggregator/channel
        use. both NULL if aggregator not supported for a certain interface type,
        e.g., LUNE_NET_IF_CHAN
    */
    net_if_recv_fwd_pkt_func_t recv_fwd_pkt;
    /* recv_free_pkt() frees packet, ONLY used for aggregator/channel scenario */
    net_if_recv_free_pkt_func_t recv_free_pkt;
    /* get_opt() must not be NULL */
    net_if_get_opt_func_t get_opt;
    /* set_opt() must not be NULL */
    net_if_set_opt_func_t set_opt;
} net_if_drv_t;

typedef struct _net_if {
    char name[LUNE_MAX_SHORT_NAME_BUF_LEN];

    /*
        NOTICE: hook not available on aggregated interface
        for now (conflict with NET_IF_IS_SOCKET())
    */
    lune_net_if_hook_t hook;

    lune_net_if_stats_t stats;
    unsigned long long byte_in_last_sec;
    unsigned long long byte_out_last_sec;
    unsigned long long pkt_in_last_sec;
    unsigned long long pkt_out_last_sec;

    lune_net_if_tcp_stats_t tcp_stats;
    unsigned int tcp_total_att_conns_last_sec;
    unsigned int tcp_total_est_conns_last_sec;
    unsigned int tcp_total_close_conns_last_sec;
    unsigned long long tcp_byte_in_last_sec;
    unsigned long long tcp_byte_out_last_sec;
    unsigned long long tcp_pkt_in_last_sec;
    unsigned long long tcp_pkt_out_last_sec;
    unsigned long long tcp_close_time_total;
    unsigned long long tcp_resp_time_total;
    unsigned long long tcp_setup_time_total;
    unsigned long long tcp_session_duration_total;

    lune_net_if_ssl_stats_t ssl_stats;
    unsigned int ssl_total_att_conns_last_sec;
    unsigned int ssl_total_est_conns_last_sec;
    unsigned int ssl_total_close_conns_last_sec;
    unsigned long long ssl_byte_dec_last_sec;
    unsigned long long ssl_byte_enc_last_sec;

    lune_timer_t stats_tmr;

    net_if_drv_t *drv;
    void *net_if_data;

    unsigned int id;

    unsigned int ref_cnt;

#define NET_IF_FLAG_ON(ifp, flag)               (((net_if_t *)(ifp))->flags & (flag))
#define NET_IF_SET_FLAG(ifp, flag)              \
    do { ((net_if_t *)(ifp))->flags |= (flag); } while (0)
#define NET_IF_CLEAR_FLAG(ifp, flag)            \
    do { ((net_if_t *)(ifp))->flags &= (~flag); } while (0)
#define NET_IF_FLAG_ACTIVE                      0x00000001
#define NET_IF_IS_ACTIVE(ifp)                   NET_IF_FLAG_ON(ifp, NET_IF_FLAG_ACTIVE)
#define NET_IF_SET_ACTIVE(ifp)                  NET_IF_SET_FLAG(ifp, NET_IF_FLAG_ACTIVE)
#define NET_IF_SET_INACTIVE(ifp)                NET_IF_CLEAR_FLAG(ifp, NET_IF_FLAG_ACTIVE)
#define NET_IF_FLAG_SOCKET                      0x00000002
#define NET_IF_IS_SOCKET(ifp)                   NET_IF_FLAG_ON(ifp, NET_IF_FLAG_SOCKET)
#define NET_IF_SET_SOCKET(ifp)                  NET_IF_SET_FLAG(ifp, NET_IF_FLAG_SOCKET)
#define NET_IF_SET_NONSOCK(ifp)                 NET_IF_CLEAR_FLAG(ifp, NET_IF_FLAG_SOCKET)
#define NET_IF_FLAG_AGGR                        0x00000004
#define NET_IF_IS_AGGR(ifp)                     NET_IF_FLAG_ON(ifp, NET_IF_FLAG_AGGR)
#define NET_IF_SET_AGGR(ifp)                    NET_IF_SET_FLAG(ifp, NET_IF_FLAG_AGGR)
#define NET_IF_SET_NONAGGR(ifp)                 NET_IF_CLEAR_FLAG(ifp, NET_IF_FLAG_AGGR)
#define NET_IF_FLAG_HOOK                        0x00000008
#define NET_IF_IS_HOOK(ifp)                     NET_IF_FLAG_ON(ifp, NET_IF_FLAG_HOOK)
#define NET_IF_SET_HOOK(ifp)                    NET_IF_SET_FLAG(ifp, NET_IF_FLAG_HOOK)
#define NET_IF_CLEAR_HOOK(ifp)                  NET_IF_CLEAR_FLAG(ifp, NET_IF_FLAG_HOOK)
#define NET_IF_FLAG_HW_RX_IPV4_CSUM             0x00000010
#define NET_IF_IS_HW_RX_IPV4_CSUM(ifp)          NET_IF_FLAG_ON(ifp, NET_IF_FLAG_HW_RX_IPV4_CSUM)
#define NET_IF_SET_HW_RX_IPV4_CSUM(ifp)         NET_IF_SET_FLAG(ifp, NET_IF_FLAG_HW_RX_IPV4_CSUM)
#define NET_IF_CLEAR_HW_RX_IPV4_CSUM(ifp)       NET_IF_CLEAR_FLAG(ifp, NET_IF_FLAG_HW_RX_IPV4_CSUM)
#define NET_IF_FLAG_HW_RX_TCP_CSUM              0x00000020
#define NET_IF_IS_HW_RX_TCP_CSUM(ifp)           NET_IF_FLAG_ON(ifp, NET_IF_FLAG_HW_RX_TCP_CSUM)
#define NET_IF_SET_HW_RX_TCP_CSUM(ifp)          NET_IF_SET_FLAG(ifp, NET_IF_FLAG_HW_RX_TCP_CSUM)
#define NET_IF_CLEAR_HW_RX_TCP_CSUM(ifp)        NET_IF_CLEAR_FLAG(ifp, NET_IF_FLAG_HW_RX_TCP_CSUM)
#define NET_IF_FLAG_HW_RX_UDP_CSUM              0x00000040
#define NET_IF_IS_HW_RX_UDP_CSUM(ifp)           NET_IF_FLAG_ON(ifp, NET_IF_FLAG_HW_RX_UDP_CSUM)
#define NET_IF_SET_HW_RX_UDP_CSUM(ifp)          NET_IF_SET_FLAG(ifp, NET_IF_FLAG_HW_RX_UDP_CSUM)
#define NET_IF_CLEAR_HW_RX_UDP_CSUM(ifp)        NET_IF_CLEAR_FLAG(ifp, NET_IF_FLAG_HW_RX_UDP_CSUM)
#define NET_IF_FLAG_HW_TX_IPV4_CSUM             0x00000080
#define NET_IF_IS_HW_TX_IPV4_CSUM(ifp)          NET_IF_FLAG_ON(ifp, NET_IF_FLAG_HW_TX_IPV4_CSUM)
#define NET_IF_SET_HW_TX_IPV4_CSUM(ifp)         NET_IF_SET_FLAG(ifp, NET_IF_FLAG_HW_TX_IPV4_CSUM)
#define NET_IF_CLEAR_HW_TX_IPV4_CSUM(ifp)       NET_IF_CLEAR_FLAG(ifp, NET_IF_FLAG_HW_TX_IPV4_CSUM)
#define NET_IF_FLAG_HW_TX_TCP_CSUM              0x00000100
#define NET_IF_IS_HW_TX_TCP_CSUM(ifp)           NET_IF_FLAG_ON(ifp, NET_IF_FLAG_HW_TX_TCP_CSUM)
#define NET_IF_SET_HW_TX_TCP_CSUM(ifp)          NET_IF_SET_FLAG(ifp, NET_IF_FLAG_HW_TX_TCP_CSUM)
#define NET_IF_CLEAR_HW_TX_TCP_CSUM(ifp)        NET_IF_CLEAR_FLAG(ifp, NET_IF_FLAG_HW_TX_TCP_CSUM)
#define NET_IF_FLAG_HW_TX_UDP_CSUM              0x00000200
#define NET_IF_IS_HW_TX_UDP_CSUM(ifp)           NET_IF_FLAG_ON(ifp, NET_IF_FLAG_HW_TX_UDP_CSUM)
#define NET_IF_SET_HW_TX_UDP_CSUM(ifp)          NET_IF_SET_FLAG(ifp, NET_IF_FLAG_HW_TX_UDP_CSUM)
#define NET_IF_CLEAR_HW_TX_UDP_CSUM(ifp)        NET_IF_CLEAR_FLAG(ifp, NET_IF_FLAG_HW_TX_UDP_CSUM)
#define NET_IF_FLAG_DPDK                        0x00000400
#define NET_IF_IS_DPDK(ifp)                     NET_IF_FLAG_ON(ifp, NET_IF_FLAG_DPDK)
#define NET_IF_SET_DPDK(ifp)                    NET_IF_SET_FLAG(ifp, NET_IF_FLAG_DPDK)
#define NET_IF_CLEAR_DPDK(ifp)                  NET_IF_CLEAR_FLAG(ifp, NET_IF_FLAG_DPDK)
    unsigned int flags;

    unsigned int rx_task_id;

#define NET_IF_IS_CAP_ENABLED(ifp)              (NULL != ((net_if_t *)(ifp))->cap_fp)
#define NET_IF_CAP_PKT(ifp, buf, len)           \
    do {                                        \
        if (NET_IF_IS_CAP_ENABLED(ifp)) {       \
            (void)cap_write_pkt(((net_if_t *)(ifp))->cap_fp,    \
                (buf), (len));                  \
        }                                       \
    } while (0)
    void *cap_fp;

#define NET_IF_GET_AGGR_NET_IF(ifp)             (((net_if_t *)ifp)->aip)
    void *aip;  /* pointer to struct _aggr_net_if */

    lune_net_if_type_en type;

#define NET_IF_GET_MTU(ifp)                     (((net_if_t *)(ifp))->mtu)
    unsigned short mtu;

    unsigned int mac_id;
    unsigned int ipv4_id;

    void *sk;

#define NET_IF_MAX_TX_DATA_RATE_UNLIMITED       (0)
    unsigned int max_tx_data_rate_per_ms;       /* unit: bytes per millisecond */
    unsigned int tx_rt_data_per_ms;             /* unit: bytes */
#define NET_IF_MAX_TX_DATA_RATE_TIMER_INTVL     (1 * LUNE_TIME_MILLISECOND)
    lune_timer_t max_tx_data_rate_tmr;
} net_if_t;

typedef struct _net_if_pcb {
    lune_net_if_socket_callback_t cb;
    net_if_t *ifp;
} net_if_pcb_t;

#define NET_IF_TCP_INC_ATTEMPTED_CONN(ifp)      \
    do { ((net_if_t *)ifp)->tcp_stats.total_att_conns++; } while (0)
#define NET_IF_TCP_INC_ESTABLISHED_CONN(ifp)    \
    do { ((net_if_t *)ifp)->tcp_stats.total_est_conns++; } while (0)
#define NET_IF_TCP_INC_CLOSED_CONN(ifp)         \
    do { ((net_if_t *)ifp)->tcp_stats.total_close_conns++; } while (0)
#define NET_IF_TCP_INC_FAILED_CONN(ifp)         \
    do { ((net_if_t *)ifp)->tcp_stats.total_fail_conns++; } while (0)
#define NET_IF_TCP_INC_ABORTED_CONN(ifp)        \
    do { ((net_if_t *)ifp)->tcp_stats.total_abrt_conns++; } while (0)
#define NET_IF_TCP_INC_CONCURRENT_CONN(ifp)     \
    do { ((net_if_t *)ifp)->tcp_stats.concurrent_conns++; } while (0)
#define NET_IF_TCP_DEC_CONCURRENT_CONN(ifp)     \
    do { ((net_if_t *)ifp)->tcp_stats.concurrent_conns--; } while (0)

#define NET_IF_TCP_ADD_DATA_IN(ifp, len)        \
    do { ((net_if_t *)ifp)->tcp_stats.byte_in += (len); } while (0)
#define NET_IF_TCP_ADD_DATA_OUT(ifp, len)       \
    do { ((net_if_t *)ifp)->tcp_stats.byte_out += (len); } while (0)
#define NET_IF_TCP_INC_PKT_IN(ifp)              \
    do { ((net_if_t *)ifp)->tcp_stats.pkt_in++; } while (0)
#define NET_IF_TCP_INC_PKT_OUT(ifp)             \
    do { ((net_if_t *)ifp)->tcp_stats.pkt_out++; } while (0)

#define NET_IF_TCP_INC_CLOSE_TIME_10MS(ifp)     \
    do { ((net_if_t *)ifp)->tcp_stats.close_time_10ms++; } while (0)
#define NET_IF_TCP_INC_CLOSE_TIME_100MS(ifp)    \
    do { ((net_if_t *)ifp)->tcp_stats.close_time_100ms++; } while (0)
#define NET_IF_TCP_INC_CLOSE_TIME_1000MS(ifp)   \
    do { ((net_if_t *)ifp)->tcp_stats.close_time_1000ms++; } while (0)
#define NET_IF_TCP_INC_CLOSE_TIME_10000MS(ifp)  \
    do { ((net_if_t *)ifp)->tcp_stats.close_time_10000ms++; } while (0)
#define NET_IF_TCP_INC_CLOSE_TIME_HIGH(ifp)     \
    do { ((net_if_t *)ifp)->tcp_stats.close_time_high++; } while (0)
#define NET_IF_TCP_INC_CLOSE_TIME_TOTAL(ifp)    \
    do { ((net_if_t *)ifp)->tcp_stats.close_time_total_num++; } while (0)
#define NET_IF_TCP_ADD_CLOSE_TIME(ifp, time)    \
    do { ((net_if_t *)ifp)->tcp_close_time_total += (time); } while (0)

static inline void net_if_tcp_add_close_time(net_if_t *ifp, unsigned int time)
{
    unsigned int time_in_millisec = time / LUNE_TIME_MILLISECOND;

    if (time_in_millisec <= 10) {
        NET_IF_TCP_INC_CLOSE_TIME_10MS(ifp);
    } else if (time_in_millisec <= 100) {
        NET_IF_TCP_INC_CLOSE_TIME_100MS(ifp);
    } else if (time_in_millisec <= 1000) {
        NET_IF_TCP_INC_CLOSE_TIME_1000MS(ifp);
    } else if (time_in_millisec <= 10000) {
        NET_IF_TCP_INC_CLOSE_TIME_10000MS(ifp);
    } else {
        NET_IF_TCP_INC_CLOSE_TIME_HIGH(ifp);
    }

    NET_IF_TCP_INC_CLOSE_TIME_TOTAL(ifp);
    NET_IF_TCP_ADD_CLOSE_TIME(ifp, time);
}

#define NET_IF_TCP_INC_RESP_TIME_10MS(ifp)      \
    do { ((net_if_t *)ifp)->tcp_stats.resp_time_10ms++; } while (0)
#define NET_IF_TCP_INC_RESP_TIME_100MS(ifp)     \
    do { ((net_if_t *)ifp)->tcp_stats.resp_time_100ms++; } while (0)
#define NET_IF_TCP_INC_RESP_TIME_1000MS(ifp)    \
    do { ((net_if_t *)ifp)->tcp_stats.resp_time_1000ms++; } while (0)
#define NET_IF_TCP_INC_RESP_TIME_10000MS(ifp)   \
    do { ((net_if_t *)ifp)->tcp_stats.resp_time_10000ms++; } while (0)
#define NET_IF_TCP_INC_RESP_TIME_HIGH(ifp)      \
    do { ((net_if_t *)ifp)->tcp_stats.resp_time_high++; } while (0)
#define NET_IF_TCP_INC_RESP_TIME_TOTAL(ifp)     \
    do { ((net_if_t *)ifp)->tcp_stats.resp_time_total_num++; } while (0)
#define NET_IF_TCP_ADD_RESP_TIME(ifp, time)     \
    do { ((net_if_t *)ifp)->tcp_resp_time_total += (time); } while (0)

static inline void net_if_tcp_add_resp_time(net_if_t *ifp, unsigned int time)
{
    unsigned int time_in_millisec = time / LUNE_TIME_MILLISECOND;

    if (time_in_millisec <= 10) {
        NET_IF_TCP_INC_RESP_TIME_10MS(ifp);
    } else if (time_in_millisec <= 100) {
        NET_IF_TCP_INC_RESP_TIME_100MS(ifp);
    } else if (time_in_millisec <= 1000) {
        NET_IF_TCP_INC_RESP_TIME_1000MS(ifp);
    } else if (time_in_millisec <= 10000) {
        NET_IF_TCP_INC_RESP_TIME_10000MS(ifp);
    } else {
        NET_IF_TCP_INC_RESP_TIME_HIGH(ifp);
    }

    NET_IF_TCP_INC_RESP_TIME_TOTAL(ifp);
    NET_IF_TCP_ADD_RESP_TIME(ifp, time);
}

#define NET_IF_TCP_INC_SETUP_TIME_10MS(ifp)     \
    do { ((net_if_t *)ifp)->tcp_stats.setup_time_10ms++; } while (0)
#define NET_IF_TCP_INC_SETUP_TIME_100MS(ifp)    \
    do { ((net_if_t *)ifp)->tcp_stats.setup_time_100ms++; } while (0)
#define NET_IF_TCP_INC_SETUP_TIME_1000MS(ifp)   \
    do { ((net_if_t *)ifp)->tcp_stats.setup_time_1000ms++; } while (0)
#define NET_IF_TCP_INC_SETUP_TIME_10000MS(ifp)  \
    do { ((net_if_t *)ifp)->tcp_stats.setup_time_10000ms++; } while (0)
#define NET_IF_TCP_INC_SETUP_TIME_HIGH(ifp)     \
    do { ((net_if_t *)ifp)->tcp_stats.setup_time_high++; } while (0)
#define NET_IF_TCP_INC_SETUP_TIME_TOTAL(ifp)    \
    do { ((net_if_t *)ifp)->tcp_stats.setup_time_total_num++; } while (0)
#define NET_IF_TCP_ADD_SETUP_TIME(ifp, time)    \
    do { ((net_if_t *)ifp)->tcp_setup_time_total += (time); } while (0)

static inline void net_if_tcp_add_setup_time(net_if_t *ifp, unsigned int time)
{
    unsigned int time_in_millisec = time / LUNE_TIME_MILLISECOND;

    if (time_in_millisec <= 10) {
        NET_IF_TCP_INC_SETUP_TIME_10MS(ifp);
    } else if (time_in_millisec <= 100) {
        NET_IF_TCP_INC_SETUP_TIME_100MS(ifp);
    } else if (time_in_millisec <= 1000) {
        NET_IF_TCP_INC_SETUP_TIME_1000MS(ifp);
    } else if (time_in_millisec <= 10000) {
        NET_IF_TCP_INC_SETUP_TIME_10000MS(ifp);
    } else {
        NET_IF_TCP_INC_SETUP_TIME_HIGH(ifp);
    }

    NET_IF_TCP_INC_SETUP_TIME_TOTAL(ifp);
    NET_IF_TCP_ADD_SETUP_TIME(ifp, time);
}

#define NET_IF_TCP_INC_SESSION_DURATION_10MS(ifp)       \
    do { ((net_if_t *)ifp)->tcp_stats.session_duration_10ms++; } while (0)
#define NET_IF_TCP_INC_SESSION_DURATION_100MS(ifp)      \
    do { ((net_if_t *)ifp)->tcp_stats.session_duration_100ms++; } while (0)
#define NET_IF_TCP_INC_SESSION_DURATION_1000MS(ifp)     \
    do { ((net_if_t *)ifp)->tcp_stats.session_duration_1000ms++; } while (0)
#define NET_IF_TCP_INC_SESSION_DURATION_10000MS(ifp)    \
    do { ((net_if_t *)ifp)->tcp_stats.session_duration_10000ms++; } while (0)
#define NET_IF_TCP_INC_SESSION_DURATION_HIGH(ifp)       \
    do { ((net_if_t *)ifp)->tcp_stats.session_duration_high++; } while (0)
#define NET_IF_TCP_INC_SESSION_DURATION_TOTAL(ifp)      \
    do { ((net_if_t *)ifp)->tcp_stats.session_duration_total_num++; } while (0)
#define NET_IF_TCP_ADD_SESSION_DURATION(ifp, time)      \
    do { ((net_if_t *)ifp)->tcp_session_duration_total += (time); } while (0)

static inline void net_if_tcp_add_session_duration(net_if_t *ifp, unsigned int time)
{
    unsigned int time_in_millisec = time / LUNE_TIME_MILLISECOND;

    if (time_in_millisec <= 10) {
        NET_IF_TCP_INC_SESSION_DURATION_10MS(ifp);
    } else if (time_in_millisec <= 100) {
        NET_IF_TCP_INC_SESSION_DURATION_100MS(ifp);
    } else if (time_in_millisec <= 1000) {
        NET_IF_TCP_INC_SESSION_DURATION_1000MS(ifp);
    } else if (time_in_millisec <= 10000) {
        NET_IF_TCP_INC_SESSION_DURATION_10000MS(ifp);
    } else {
        NET_IF_TCP_INC_SESSION_DURATION_HIGH(ifp);
    }

    NET_IF_TCP_INC_SESSION_DURATION_TOTAL(ifp);
    NET_IF_TCP_ADD_SESSION_DURATION(ifp, time);
}

#define NET_IF_SSL_INC_ATTEMPTED_CONN(ifp)      \
    do { ((net_if_t *)ifp)->ssl_stats.total_att_conns++; } while (0)
#define NET_IF_SSL_INC_ESTABLISHED_CONN(ifp)    \
    do { ((net_if_t *)ifp)->ssl_stats.total_est_conns++; } while (0)
#define NET_IF_SSL_INC_CLOSED_CONN(ifp)         \
    do { ((net_if_t *)ifp)->ssl_stats.total_close_conns++; } while (0)
#define NET_IF_SSL_INC_FAILED_CONN(ifp)         \
    do { ((net_if_t *)ifp)->ssl_stats.total_fail_conns++; } while (0)
#define NET_IF_SSL_INC_ABORTED_CONN(ifp)        \
    do { ((net_if_t *)ifp)->ssl_stats.total_abrt_conns++; } while (0)
#define NET_IF_SSL_INC_CONCURRENT_CONN(ifp)     \
    do { ((net_if_t *)ifp)->ssl_stats.concurrent_conns++; } while (0)
#define NET_IF_SSL_DEC_CONCURRENT_CONN(ifp)     \
    do { ((net_if_t *)ifp)->ssl_stats.concurrent_conns--; } while (0)

#define NET_IF_SSL_ADD_DATA_DEC(ifp, len)       \
    do { ((net_if_t *)ifp)->ssl_stats.byte_dec += (len); } while (0)
#define NET_IF_SSL_ADD_DATA_ENC(ifp, len)       \
    do { ((net_if_t *)ifp)->ssl_stats.byte_enc += (len); } while (0)

static inline void net_if_hold(net_if_t *ifp)
{
    ++ifp->ref_cnt;
}

static inline void net_if_put(net_if_t *ifp)
{
    if (0 == --ifp->ref_cnt) {
        lune_free_mt(ifp);
    }
}

int net_if_send_pkt(void *p, pbuf_t *pbuf);

int net_if_init(void);
void net_if_fini(void);

int net_if_local_init(void);
void net_if_local_fini(void);

net_if_t *net_if_get_net_if_by_entry(lune_id_type_en type, void *entry);
net_if_t *net_if_get_net_if_by_id(unsigned int id);

void net_if_recv_pkts_and_process(net_if_t *ifp);
int net_if_process_single_net_if_recv_func(net_if_t *ifp,
    unsigned char *buf, unsigned int len, int skip_cap);

#define NET_IF_GET_CURR_TX_PBUF()               (g_net_if_curr_tx_pbuf)
#define NET_IF_SET_CURR_TX_PBUF(pbuf)           \
    do { g_net_if_curr_tx_pbuf = (pbuf_t *)(pbuf); } while (0)
extern __thread pbuf_t *g_net_if_curr_tx_pbuf;

#define NET_IF_GET_CURR_NET_IF()                (g_net_if_curr_ifp)
#define NET_IF_SET_CURR_NET_IF(ifp)             \
    do { g_net_if_curr_ifp = (net_if_t *)(ifp); } while (0)
#define NET_IF_CLEAR_CURR_NET_IF()              NET_IF_SET_CURR_NET_IF(NULL)
extern __thread net_if_t *g_net_if_curr_ifp;

extern net_if_drv_t g_net_if_drv_array[LUNE_NET_IF_MAX];

#include "net/socket.h"

extern socket_ops_t g_socket_ops_net_if;

#endif