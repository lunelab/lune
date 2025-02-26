/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2024 Lune Reseau, Inc.
 */

#ifndef __LUNE_NET_IF_H__
#define __LUNE_NET_IF_H__

#include "lune/ip.h"
#include "lune/mac.h"

#ifdef __cplusplus
extern "C" {
#endif

#define LUNE_NET_IF_MAX_MTU                     (9198)
#define LUNE_NET_IF_MIN_MTU                     (68)

#define LUNE_NET_IF_MIN_PKT_SIZE                (60)

#define LUNE_NET_IF_MAX_NUM_IN_BIT              (6)
#define LUNE_NET_IF_MAX_NUM                     (1 << LUNE_NET_IF_MAX_NUM_IN_BIT)
#define LUNE_NET_IF_MAX_NUM_MASK                (LUNE_NET_IF_MAX_NUM - 1)

typedef enum _lune_net_if_type {
    LUNE_NET_IF_STD = 0,
    LUNE_NET_IF_CHAN,
    LUNE_NET_IF_DPDK,
    LUNE_NET_IF_DPDK_CHAN,
    LUNE_NET_IF_DPDK_QUEUE,
    LUNE_NET_IF_DPDK_QUEUE_CHAN,
    LUNE_NET_IF_VIRT,
    LUNE_NET_IF_MAX,
} lune_net_if_type_en;

typedef enum _lune_net_if_opt {
    /* get options */
    LUNE_NET_IF_OPT_GET_MTU = 0,
    LUNE_NET_IF_OPT_GET_STATS,
    LUNE_NET_IF_OPT_GET_SSL_STATS,
    LUNE_NET_IF_OPT_GET_TCP_STATS,
    LUNE_NET_IF_OPT_GET_CHAN_ID,
    /* set options */
    LUNE_NET_IF_OPT_CLEAR_ALL_STATS = 256,
    LUNE_NET_IF_OPT_SET_MTU,
    LUNE_NET_IF_OPT_SET_AGGR,
    LUNE_NET_IF_OPT_CLEAR_AGGR,
    LUNE_NET_IF_OPT_PCAP_START,
    LUNE_NET_IF_OPT_PCAP_STOP,
    LUNE_NET_IF_OPT_DPDK_QUEUE_PCAP_START,
    LUNE_NET_IF_OPT_DPDK_QUEUE_PCAP_STOP,
    LUNE_NET_IF_OPT_SET_HOOK,
    LUNE_NET_IF_OPT_CLEAR_HOOK,
    LUNE_NET_IF_OPT_DPDK_QUEUE_SET_DISTRIB,
    LUNE_NET_IF_OPT_DPDK_QUEUE_CLEAR_DISTRIB,
    LUNE_NET_IF_OPT_MAX = 512,
} lune_net_if_opt_en;

typedef struct _lune_net_if_stats {
    unsigned long long pkt_in;
    unsigned long long pkt_out;
    unsigned long long pkt_in_dropped;
    unsigned long long pkt_out_dropped;
    unsigned long long pkt_in_ipv4_csum_err;
    unsigned long long pkt_in_l4_csum_err;
    unsigned long long byte_in;
    unsigned long long byte_out;
    unsigned long long pkt_in_rate;
    unsigned long long pkt_out_rate;
    unsigned long long byte_in_rate;
    unsigned long long byte_out_rate;
} lune_net_if_stats_t;

/* DON'T CHANGE ORDER */
typedef struct _lune_net_if_tcp_state_stats {
    unsigned int syn_recv;
    unsigned int syn_sent;
    unsigned int established;
    unsigned int fin_wait_1;
    unsigned int fin_wait_2;
    unsigned int closing;
    unsigned int time_wait;
    unsigned int close_wait;
    unsigned int last_ack;
    unsigned int listen;
    /* TCP_CLOSED unneeded */
} lune_net_if_tcp_state_stats_t;

typedef struct _lune_net_if_tcp_stats {
    /* attempted connection, actively attempted but yet established */
    unsigned int total_att_conns;
    /* rate of attempted connection */
    unsigned int att_conn_rate;
    /* established connection, both active and passive */
    unsigned int total_est_conns;
    /* rate of established connection */
    unsigned int est_conn_rate;
    /* normally closed connection after establishment, including RST closure */
    unsigned int total_close_conns;
    /* rate of closed connection */
    unsigned int close_conn_rate;
    /* closed connection after establishment, due to some error */
    unsigned int total_fail_conns;
    /* aborted connection, actively attempted but closed before establishment */
    unsigned int total_abrt_conns;
    /* currently established connection */
    unsigned int concurrent_conns;

    /* bytes received of established connection */
    unsigned long long byte_in;
    /* bytes sent of established connection */
    unsigned long long byte_out;
    /* received byte rate of established connection */
    unsigned long long byte_in_rate;
    /* sent byte rate of established connection */
    unsigned long long byte_out_rate;
    /* pkts received of established connection */
    unsigned long long pkt_in;
    /* pkts sent of established connection */
    unsigned long long pkt_out;
    /* received pkt rate of established connection */
    unsigned long long pkt_in_rate;
    /* sent pkt rate of established connection */
    unsigned long long pkt_out_rate;

    /* close time: from first FIN+ACK to last ACK */
    float avg_close_time_ms;
    unsigned int close_time_10ms;
    unsigned int close_time_100ms;
    unsigned int close_time_1000ms;
    unsigned int close_time_10000ms;
    unsigned int close_time_high;
    unsigned int close_time_total_num;

    /* response time: from sending SYN to receiving SYN+ACK */
    float avg_resp_time_ms;
    unsigned int resp_time_10ms;
    unsigned int resp_time_100ms;
    unsigned int resp_time_1000ms;
    unsigned int resp_time_10000ms;
    unsigned int resp_time_high;
    unsigned int resp_time_total_num;

    /* setup time: from SYN to connection establishment */
    float avg_setup_time_ms;
    unsigned int setup_time_10ms;
    unsigned int setup_time_100ms;
    unsigned int setup_time_1000ms;
    unsigned int setup_time_10000ms;
    unsigned int setup_time_high;
    unsigned int setup_time_total_num;

    /* session duration: period of established connection */
    float avg_session_duration_ms;
    unsigned int session_duration_10ms;
    unsigned int session_duration_100ms;
    unsigned int session_duration_1000ms;
    unsigned int session_duration_10000ms;
    unsigned int session_duration_high;
    unsigned int session_duration_total_num;

    lune_net_if_tcp_state_stats_t state_stats;
} lune_net_if_tcp_stats_t;

typedef struct _lune_net_if_ssl_stats {
    /* attempted connection, actively attempted but yet established */
    unsigned int total_att_conns;
    /* rate of attempted connection */
    unsigned int att_conn_rate;
    /* established connection, both active and passive */
    unsigned int total_est_conns;
    /* rate of established connection */
    unsigned int est_conn_rate;
    /* normally closed connection after establishment, including RST closure */
    unsigned int total_close_conns;
    /* rate of closed connection */
    unsigned int close_conn_rate;
    /* closed connection after establishment, due to some error */
    unsigned int total_fail_conns;
    /* aborted connection, actively attempted but closed before establishment */
    unsigned int total_abrt_conns;
    /* currently established connection */
    unsigned int concurrent_conns;

    /* bytes decrypted of established connection */
    unsigned long long byte_dec;
    /* bytes encrypted of established connection */
    unsigned long long byte_enc;
    /* decrypted byte rate of established connection */
    unsigned long long byte_dec_rate;
    /* encrypted byte rate of established connection */
    unsigned long long byte_enc_rate;
} lune_net_if_ssl_stats_t;

typedef int (*lune_net_if_socket_recv_callback_func_t)(void *,
    const unsigned char *, unsigned int);
typedef struct _lune_net_if_socket_callback {
    lune_net_if_socket_recv_callback_func_t recv;
    void *data;
} lune_net_if_socket_callback_t;

/*
    LUNE_NET_IF_HOOK_PKT_NONE - just watch, packet will still be sent or received right after
    LUNE_NET_IF_HOOK_PKT_DROP - drop it, packet won't be sent or received any further
*/
#define LUNE_NET_IF_HOOK_PKT_NONE          (0)
#define LUNE_NET_IF_HOOK_PKT_DROP          (1)
typedef int (*lune_net_if_send_hook_func_t)(void *, const unsigned char *, unsigned int);
typedef int (*lune_net_if_recv_hook_func_t)(void *, const unsigned char *, unsigned int);
typedef struct _lune_net_if_hook {
    lune_net_if_send_hook_func_t send;
    lune_net_if_recv_hook_func_t recv;
    void *data;
} lune_net_if_hook_t;

typedef struct _lune_net_if_pcap {
    const char *file_name;
} lune_net_if_pcap_t;

typedef unsigned int (*lune_net_if_aggr_recv_dist_func_t)
    (void *, const unsigned char *, unsigned int);

typedef enum _lune_net_if_aggr_type_en {
    LUNE_NET_IF_AGGR_MAC_CLIENT = 0,
    LUNE_NET_IF_AGGR_MAC_SERVER,
    LUNE_NET_IF_AGGR_IP_CLIENT,
    LUNE_NET_IF_AGGR_IP_SERVER,
    LUNE_NET_IF_AGGR_CUSTOM,
    LUNE_NET_IF_AGGR_MAX,
} lune_net_if_aggr_type_en;

typedef struct _lune_net_if_aggr_conf {
    unsigned int chan_num;
    lune_net_if_aggr_type_en type;
    union {
        struct {
            lune_mac_addr_t start_mac;
            lune_mac_addr_t end_mac;
            unsigned int step;
        } mac;
        struct {
            lune_ip_addr_t start_ip;
            lune_ip_addr_t end_ip;
            unsigned int step;
        } ip;
        struct {
#define LUNE_NET_IF_AGGR_RECV_DIST_DROP    ((unsigned int)-1)
            lune_net_if_aggr_recv_dist_func_t dist;
            void *data;
        } cust;
    };
} lune_net_if_aggr_conf_t;

typedef struct _lune_net_if_dpdk_conf {
    unsigned short txq_num;
} lune_net_if_dpdk_conf_t;

typedef enum _lune_net_if_dpdk_rss_type_en {
    LUNE_NET_IF_DPDK_RSS_TYPE_L3_NONE = 0,
    LUNE_NET_IF_DPDK_RSS_TYPE_L3_SRC,  /* server */
    LUNE_NET_IF_DPDK_RSS_TYPE_L3_DST,  /* client */
    LUNE_NET_IF_DPDK_RSS_TYPE_MAX,
} lune_net_if_dpdk_rss_type_en;

typedef struct _lune_net_if_dpdk_queue_conf {
    unsigned short rxq_num;
    unsigned short txq_num;
    lune_net_if_dpdk_rss_type_en rss_type;
} lune_net_if_dpdk_queue_conf_t;

typedef struct _lune_net_if_nrt_aggr_conf {
    lune_net_if_type_en chan_type;
    lune_net_if_aggr_conf_t conf;
} lune_net_if_nrt_aggr_conf_t;

typedef struct _lune_net_if_nrt_conf {
    /* type-specific interface configuration */
    union {
        lune_net_if_dpdk_conf_t dpdk_conf;
        lune_net_if_dpdk_queue_conf_t dpdk_queue_conf;
    };
    /* skip if not for aggregated interface */
    lune_net_if_nrt_aggr_conf_t aggr_conf;
    /*
        single NA or single NP:             non-aggregated interface
        single NA and single/multiple NP:   aggregated interface
        multiple NA and multiple NP:        aggregated dpdk multi-queue interface
        zero NA and multiple NP:            dpdk multi-queue interface
    */
    const char *cpu_list;
} lune_net_if_nrt_conf_t;

/*
    hereafter the APIs allow you to operate creation/deletion/enablement/disablement
    of network interface on either runtime or non-runtime core. just note that the APIs are
    not thread-safe and once called on non-runtime core, caller MUST guarantee they are called
    one by one.

    start/stop for single interface:
    1. add interface
    2. enable interface
    3. disable interface
    4. delete interface

    start/stop for aggregated interface(s)
    1. add aggregated interface(s)
    2. add channel interfaces
    3. enable aggregated interface(s)
    4. enable channel interfaces (aggregated interface starts rx/tx after all channel interfaces
       enabled)
    5. disable channel interfaces (aggregated interface stops rx/tx after disabling first channel
       interface)
    6. disable aggregated interface
    7. delete channel interfaces
    8. delete aggregated interface(s)
*/
unsigned int lune_add_net_if(lune_net_if_type_en type,
    const char *name, const void *conf_val, unsigned int conf_len);
int lune_del_net_if(unsigned int id);
unsigned int lune_get_net_if(lune_net_if_type_en type, const char *name);
int lune_enable_net_if(unsigned int id);
int lune_disable_net_if(unsigned int id);
int lune_get_net_if_opt(unsigned int id,
    lune_net_if_opt_en opt, void *opt_val, unsigned int opt_len);
int lune_set_net_if_opt(unsigned int id,
    lune_net_if_opt_en opt, const void *opt_val, unsigned int opt_len);

int lune_net_if_send(unsigned int id, const unsigned char *buf, unsigned int len);

/*
    virtual interface only
*/
int lune_connect_net_if(unsigned int id1, unsigned id2);
int lune_disconnect_net_if(unsigned int id);

#ifdef __cplusplus
}
#endif

#endif