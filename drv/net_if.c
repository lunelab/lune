/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2024 Lune Reseau, Inc.
 */

#include "lune/cpu.h"
#include "lune/ipv4.h"
#include "lune/log.h"
#include "lune/mac.h"
#include "lune/mem.h"
#include "lune/net_if.h"
#include "lune/os/linux.h"
#include "lune/socket.h"
#include "lune/time.h"

#include "drv/aggr.h"
#ifdef LUNE_BUILD_DPDK
#include "drv/dpdk/net_if_dpdk.h"
#include "drv/dpdk/net_if_dpdk_chan.h"
#include "drv/dpdk/net_if_dpdk_queue.h"
#include "drv/dpdk/net_if_dpdk_queue_chan.h"
#endif
#include "drv/net_if.h"
#include "drv/net_if_chan.h"
#include "drv/net_if_std.h"
#include "drv/net_if_virt.h"
#include "kernel/sched.h"
#include "net/socket.h"
#include "res/cpu.h"
#include "rt/comm.h"
#include "rt/core.h"
#include "utils/cap.h"

#define NET_IF_DRIVER_DECL(t, drv)                              \
__attribute__((constructor)) static void net_if_reg_drv_##t(void) {         \
    lune_assert(LUNE_NET_IF_MAX > (drv).type);                  \
    lune_assert(NULL != (drv).name);                            \
    lune_assert(NULL != (drv).add_net_if);                      \
    if (NULL == (drv).is_up) {                                  \
        lune_assert(NULL == (drv).set_up && NULL == (drv).set_down);        \
    } else {                                                    \
        lune_assert(NULL != (drv).set_up);                      \
    }                                                           \
    lune_assert(NULL != (drv).send);                            \
    lune_assert(NULL != (drv).recv || NULL != (drv).recv_pkts); \
    lune_assert(NULL != (drv).recv_done);                       \
    lune_assert(NULL != (drv).get_opt);                         \
    lune_assert(NULL != (drv).set_opt);                         \
    memcpy(&g_net_if_drv_array[(drv).type], &(drv), sizeof(net_if_drv_t));  \
}

#define NET_IF_GET_MAX_ETH_PKT_SIZE(ifp)                        (((ifp)->mtu) + LUNE_ETH_HDR_LEN)
#define NET_IF_GET_MAX_VLAN_PKT_SIZE(ifp)                       \
    (((ifp)->mtu) + LUNE_ETH_HDR_LEN + LUNE_VLAN_FIELD_LEN)
#define NET_IF_GET_MAX_QINQ_PKT_SIZE(ifp)                       \
    (((ifp)->mtu) + LUNE_ETH_HDR_LEN + LUNE_VLAN_FIELD_LEN * 2)

/*
    non-runtime network interface id is composed of:

    | reserved (24-bit)  | non-runtime flag (1-bit)  | aggregation flag (1-bit)  | interface id (6-bit)  |

    non-runtime flag:
        identify whether id is created on runtime core or non-runtime core. 1 if it's assigned by
        lune_add_net_if() on non-runtime core, 0 otherwise
    aggregation flag:
        identify whether id is a single interface or an aggregated interface. 1 if it's an aggregated
        interface or a dpdk queue interface (aggregated in dpdk) or a dpdk queue aggregated interface
        (two-level aggregation, first in dpdk and second in lune), 0 otherwise (i.e., single interface)
    interface id:
        internal network interface id
*/

/*
    convert non-runtime internal id to non-runtime id (application-aware)
*/
#define NET_IF_CONV_NRT_INT_ID_TO_NRT_ID(id, is_aggr)           \
    ((is_aggr > 0 ? 1 : 0) << (LUNE_NET_IF_MAX_NUM_IN_BIT + 1)) \
    | (1 << LUNE_NET_IF_MAX_NUM_IN_BIT)                         \
    | (id)

#define NET_IF_IS_NRT_ID(id)                                    \
    ((id) & (1 << LUNE_NET_IF_MAX_NUM_IN_BIT))
#define NET_IF_IS_NRT_ID_AGGR(nrt_id)                           \
    ((nrt_id) & (1 << (LUNE_NET_IF_MAX_NUM_IN_BIT + 1)))
#define NET_IF_GET_NRT_INT_ID(nrt_id)                           \
    ((nrt_id) & LUNE_NET_IF_MAX_NUM_MASK)

#define NET_IF_NRT_WAIT_RESP_SLEEP_USEC                         (500)

typedef struct _net_if_nrt_net_if {
    unsigned int nrt_id;        /* non-runtime id, see declaration above */
    union {
        struct {
            unsigned int id;    /* runtime id */
            unsigned int core_id;
        } non_aggr;
        struct {
            unsigned int chan_id_array[LUNE_MAX_CORE_NUM];
            unsigned int core_id_array[LUNE_MAX_CORE_NUM];
            unsigned int aggr_id_array[LUNE_MAX_CORE_NUM];
            unsigned int chan_num;
            unsigned int core_num;
            unsigned int aggr_num;
        } aggr;
    };
} net_if_nrt_net_if_t;

typedef struct _net_if_comm_add_net_if_conf {
    lune_net_if_type_en type;
    unsigned int is_aggr;
    char name[LUNE_MAX_SHORT_NAME_BUF_LEN];
    union {
        lune_net_if_dpdk_conf_t dpdk_conf;
        lune_net_if_dpdk_queue_conf_t dpdk_queue_conf;
    };
    union {
        lune_net_if_aggr_conf_t aggr_conf;
    };
} net_if_comm_add_net_if_conf_t;

typedef struct _net_if_comm_del_net_if_conf {
    unsigned int id;
} net_if_comm_del_net_if_conf_t;

typedef struct _net_if_comm_enable_net_if_conf {
    unsigned int id;
} net_if_comm_enable_net_if_conf_t;

typedef struct _net_if_comm_disable_net_if_conf {
    unsigned int id;
} net_if_comm_disable_net_if_conf_t;

typedef struct _net_if_comm_get_net_if_opt_conf {
    unsigned int id;
    lune_net_if_opt_en opt;
    void *opt_val;
    unsigned int opt_len;
} net_if_comm_get_net_if_opt_conf_t;

typedef struct _net_if_comm_set_net_if_opt_conf {
    unsigned int id;
    lune_net_if_opt_en opt;
    const void *opt_val;
    unsigned int opt_len;
} net_if_comm_set_net_if_opt_conf_t;

typedef struct _net_if_comm_connect_net_if_conf {
    unsigned int id;
    unsigned int peer_id;
    unsigned int peer_core_id;
} net_if_comm_connect_net_if_conf_t;

typedef struct _net_if_comm_disconnect_net_if_conf {
    unsigned int id;
} net_if_comm_disconnect_net_if_conf_t;

/*
    get statistics per second
*/
#define NET_IF_GET_STATS_INTVL                                  (1 * LUNE_TIME_SECOND)

#define NET_IF_AGGR_MAX_RECV_PKT_NUM_PER_RECV_CALL              (15)
#define NET_IF_NON_AGGR_MAX_RECV_PKT_NUM_PER_RECV_CALL          (1)

net_if_drv_t g_net_if_drv_array[LUNE_NET_IF_MAX] = {{0}};
static __thread net_if_drv_t s_net_if_drv_array[LUNE_NET_IF_MAX];

static __thread unsigned int s_net_if_rt_cnt;
static __thread unsigned int s_net_if_rt_array_offset;
static __thread net_if_t *s_net_if_rt_array[LUNE_NET_IF_MAX_NUM];

static unsigned int s_net_if_nrt_cnt;
static unsigned int s_net_if_nrt_array_offset;
static net_if_nrt_net_if_t *s_net_if_nrt_array[LUNE_NET_IF_MAX_NUM];

__thread net_if_t *g_net_if_curr_ifp;

__thread pbuf_t *g_net_if_curr_tx_pbuf;

static void net_if_update_stats_timer_func(net_if_t *ifp)
{
    int err;

    lune_assert(NULL != ifp);

    if (0 != (err = ifp->drv->get_opt(ifp->net_if_data,
        NET_IF_OPT_GET_STATS, (unsigned char *)&ifp->stats, sizeof(ifp->stats)))) {
        lune_log(LUNE_WARN, "failed to get statistics on %s: %s", ifp->name, ERR_GET_LAST_ERR_STR());
    }

    ifp->stats.byte_in_rate = ifp->stats.byte_in - ifp->byte_in_last_sec;
    ifp->byte_in_last_sec = ifp->stats.byte_in;
    ifp->stats.byte_out_rate = ifp->stats.byte_out - ifp->byte_out_last_sec;
    ifp->byte_out_last_sec = ifp->stats.byte_out;
    ifp->stats.pkt_in_rate = ifp->stats.pkt_in - ifp->pkt_in_last_sec;
    ifp->pkt_in_last_sec = ifp->stats.pkt_in;
    ifp->stats.pkt_out_rate = ifp->stats.pkt_out - ifp->pkt_out_last_sec;
    ifp->pkt_out_last_sec = ifp->stats.pkt_out;

    if (NET_IF_IS_AGGR(ifp)) {
        aggr_net_if_update_tcp_stats(ifp);
    } else {
        ifp->tcp_stats.att_conn_rate = ifp->tcp_stats.total_att_conns - ifp->tcp_total_att_conns_last_sec;
        ifp->tcp_total_att_conns_last_sec = ifp->tcp_stats.total_att_conns;
        ifp->tcp_stats.est_conn_rate = ifp->tcp_stats.total_est_conns - ifp->tcp_total_est_conns_last_sec;
        ifp->tcp_total_est_conns_last_sec = ifp->tcp_stats.total_est_conns;
        ifp->tcp_stats.close_conn_rate = ifp->tcp_stats.total_close_conns - ifp->tcp_total_close_conns_last_sec;
        ifp->tcp_total_close_conns_last_sec = ifp->tcp_stats.total_close_conns;

        ifp->tcp_stats.byte_in_rate = ifp->tcp_stats.byte_in - ifp->tcp_byte_in_last_sec;
        ifp->tcp_byte_in_last_sec = ifp->tcp_stats.byte_in;
        ifp->tcp_stats.byte_out_rate = ifp->tcp_stats.byte_out - ifp->tcp_byte_out_last_sec;
        ifp->tcp_byte_out_last_sec = ifp->tcp_stats.byte_out;
        ifp->tcp_stats.pkt_in_rate = ifp->tcp_stats.pkt_in - ifp->tcp_pkt_in_last_sec;
        ifp->tcp_pkt_in_last_sec = ifp->tcp_stats.pkt_in;
        ifp->tcp_stats.pkt_out_rate = ifp->tcp_stats.pkt_out - ifp->tcp_pkt_out_last_sec;
        ifp->tcp_pkt_out_last_sec = ifp->tcp_stats.pkt_out;

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

        /* ssl statistics */
        ifp->ssl_stats.att_conn_rate = ifp->ssl_stats.total_att_conns - ifp->ssl_total_att_conns_last_sec;
        ifp->ssl_total_att_conns_last_sec = ifp->ssl_stats.total_att_conns;
        ifp->ssl_stats.est_conn_rate = ifp->ssl_stats.total_est_conns - ifp->ssl_total_est_conns_last_sec;
        ifp->ssl_total_est_conns_last_sec = ifp->ssl_stats.total_est_conns;
        ifp->ssl_stats.close_conn_rate = ifp->ssl_stats.total_close_conns - ifp->ssl_total_close_conns_last_sec;
        ifp->ssl_total_close_conns_last_sec = ifp->ssl_stats.total_close_conns;
    }
}

static unsigned int net_if_rt_get_new_id(void)
{
    int i;

    if (LUNE_NET_IF_MAX_NUM == s_net_if_rt_cnt) {
        ERR_SET_ERR(LUNE_ERR_EXCEED_LIMITS);
        return LUNE_INVALID_ID;
    }

    i = s_net_if_rt_array_offset;
    while (NULL != s_net_if_rt_array[i]) {
        i = ((i + 1) % LUNE_NET_IF_MAX_NUM);
    }

    return i;
}

static unsigned int net_if_nrt_get_new_id(void)
{
    int i;

    if (LUNE_NET_IF_MAX_NUM == s_net_if_nrt_cnt) {
        ERR_SET_ERR(LUNE_ERR_EXCEED_LIMITS);
        return LUNE_INVALID_ID;
    }

    i = s_net_if_nrt_array_offset;
    while (NULL != s_net_if_nrt_array[i]) {
        i = ((i + 1) % LUNE_NET_IF_MAX_NUM);
    }

    return i;
}

static void net_if_clear_max_tx_data_rate_per_ms_timer_func(net_if_t *ifp)
{
    ifp->tx_rt_data_per_ms = 0;
}

static net_if_t *net_if_add_net_if(lune_net_if_type_en type,
    net_if_drv_t *drv, const char *name, const void *conf_val, unsigned int conf_len)
{
    net_if_t *ifp;
    int err;
    unsigned int max_tx_data_rate;
    unsigned short flags;

    if (NULL == (ifp = lune_malloc_mt(sizeof(net_if_t)))) {
        goto ERR_1;
    }

    /*
        id assigned before add_net_if() as add_net_if() of some drivers uses id as one of
        the factors to determine a unique interface, such as virtual interface driver
    */
    if (unlikely(LUNE_INVALID_ID == (ifp->id = net_if_rt_get_new_id()))) {
        goto ERR_2;
    }

    ifp->drv = drv;
    ifp->type = type;
    if (0 != (err = ifp->drv->add_net_if(ifp, name, conf_val, conf_len, &ifp->net_if_data))) {
        goto ERR_2;
    }

    if (0 != (err = ifp->drv->get_opt(ifp->net_if_data,
        NET_IF_OPT_GET_MTU, (unsigned char *)&ifp->mtu, sizeof(ifp->mtu)))) {
        goto ERR_3;
    }

    if (0 != (err = ifp->drv->get_opt(ifp->net_if_data,
        NET_IF_OPT_GET_MAX_DATA_RATE, (unsigned char *)&max_tx_data_rate, sizeof(max_tx_data_rate)))) {
        if (err != -LUNE_ERR_NOT_SUPPORTED) {
            goto ERR_3;
        }

        /* default it to unlimited if unspecified */
        ifp->max_tx_data_rate_per_ms = NET_IF_MAX_TX_DATA_RATE_UNLIMITED;
    } else {
        if (NET_IF_MAX_TX_DATA_RATE_UNLIMITED == max_tx_data_rate) {
            ifp->max_tx_data_rate_per_ms = NET_IF_MAX_TX_DATA_RATE_UNLIMITED;
        } else {
            /* convert data rate from bps to bytes per millisecond */
            ifp->max_tx_data_rate_per_ms = max_tx_data_rate / 8 / 1000;
        }
    }
    ifp->tx_rt_data_per_ms = 0;
    timer_init_timer(&ifp->max_tx_data_rate_tmr, LUNE_TIMER_RECURRING, LUNE_TIMER_RES_HIGH,
        (lune_timer_func_t)net_if_clear_max_tx_data_rate_per_ms_timer_func, ifp);

    if (unlikely(ifp->mtu < LUNE_NET_IF_MIN_MTU || ifp->mtu > LUNE_NET_IF_MAX_MTU)) {
        ERR_SET_ERR(LUNE_ERR_INVALID_MTU);
        goto ERR_3;
    }

    if (0 != (err = ifp->drv->get_opt(ifp->net_if_data,
        NET_IF_OPT_GET_HW_CSUM, (unsigned char *)&flags, sizeof(flags)))) {
        goto ERR_3;
    }

    ifp->flags = 0;

    if (NET_IF_OPT_IS_HW_TX_CSUM_IPV4(flags)) {
        NET_IF_SET_HW_TX_IPV4_CSUM(ifp);
    }
    if (NET_IF_OPT_IS_HW_TX_CSUM_TCP(flags)) {
        NET_IF_SET_HW_TX_TCP_CSUM(ifp);
    }
    if (NET_IF_OPT_IS_HW_TX_CSUM_UDP(flags)) {
        NET_IF_SET_HW_TX_UDP_CSUM(ifp);
    }

    if (NET_IF_OPT_IS_HW_RX_CSUM_IPV4(flags)) {
        NET_IF_SET_HW_RX_IPV4_CSUM(ifp);
    }
    if (NET_IF_OPT_IS_HW_RX_CSUM_TCP(flags)) {
        NET_IF_SET_HW_RX_TCP_CSUM(ifp);
    }
    if (NET_IF_OPT_IS_HW_RX_CSUM_UDP(flags)) {
        NET_IF_SET_HW_RX_UDP_CSUM(ifp);
    }

#ifdef LUNE_BUILD_DPDK
    if (LUNE_NET_IF_DPDK <= type && LUNE_NET_IF_DPDK_QUEUE_CHAN >= type) {
        NET_IF_SET_DPDK(ifp);
    }
#endif

    s_net_if_rt_cnt++;
    s_net_if_rt_array_offset = ((ifp->id + 1) % LUNE_NET_IF_MAX_NUM);
    s_net_if_rt_array[ifp->id] = ifp;

    strcpy(ifp->name, name);
    memset(&ifp->hook, 0x00, sizeof(ifp->hook));
    memset(&ifp->stats, 0x00, sizeof(ifp->stats));
    ifp->byte_in_last_sec = 0;
    ifp->byte_out_last_sec = 0;
    ifp->pkt_in_last_sec = 0;
    ifp->pkt_out_last_sec = 0;
    memset(&ifp->tcp_stats, 0x00, sizeof(ifp->tcp_stats));
    ifp->tcp_total_att_conns_last_sec = 0;
    ifp->tcp_total_est_conns_last_sec = 0;
    ifp->tcp_total_close_conns_last_sec = 0;
    ifp->tcp_byte_in_last_sec = 0;
    ifp->tcp_byte_out_last_sec = 0;
    ifp->tcp_pkt_in_last_sec = 0;
    ifp->tcp_pkt_out_last_sec = 0;
    ifp->tcp_close_time_total = 0;
    ifp->tcp_resp_time_total = 0;
    ifp->tcp_setup_time_total = 0;
    ifp->tcp_session_duration_total = 0;
    memset(&ifp->ssl_stats, 0x00, sizeof(ifp->ssl_stats));
    ifp->ssl_total_att_conns_last_sec = 0;
    ifp->ssl_total_est_conns_last_sec = 0;
    ifp->ssl_total_close_conns_last_sec = 0;
    ifp->ssl_total_att_conns_last_sec = 0;
    ifp->ssl_total_est_conns_last_sec = 0;
    ifp->ssl_total_close_conns_last_sec = 0;
    ifp->ssl_byte_dec_last_sec = 0;
    ifp->ssl_byte_enc_last_sec = 0;
    timer_init_timer(&ifp->stats_tmr, LUNE_TIMER_RECURRING,
        LUNE_TIMER_RES_HIGH, (lune_timer_func_t)net_if_update_stats_timer_func, ifp);
    ifp->ref_cnt = 0;
    ifp->rx_task_id = LUNE_INVALID_ID;
    ifp->cap_fp = NULL;
    ifp->sk = NULL;

    net_if_hold(ifp);

    return ifp;

ERR_3:
    lune_assert(!ifp->drv->del_net_if(ifp->net_if_data));

ERR_2:
    lune_free_mt(ifp);

ERR_1:
    lune_log(LUNE_WARN, "failed to add interface %s: %s", name, ERR_GET_LAST_ERR_STR());

    return NULL;
}

net_if_t *net_if_get_net_if_by_entry(lune_id_type_en type, void *entry)
{
    switch (type) {
    case LUNE_ID_NET_IF:
        return entry;
    case LUNE_ID_MAC:
        return net_if_get_net_if_by_entry(MAC_GET_SUB_TYPE(entry), MAC_GET_SUB_ENTRY(entry));
    case LUNE_ID_IPV4:
    case LUNE_ID_IPV6:
        return net_if_get_net_if_by_entry(IP_GET_SUB_TYPE(entry), IP_GET_SUB_ENTRY(entry));
    case LUNE_ID_SOCKET:
        /* fall through: not supported */
    default:
        lune_assert(0);
        return NULL;
    }
}

net_if_t *net_if_get_net_if_by_id(unsigned int id)
{
#ifdef LUNE_DEBUG
    lune_assert(CORE_IS_RT_CORE());
#endif

    if (NET_IF_IS_NRT_ID(id)) {
        int i, j;
        unsigned int core_id = (unsigned int)CORE_GET_ID();
        net_if_nrt_net_if_t *nrt_ifp = s_net_if_nrt_array[NET_IF_GET_NRT_INT_ID(id)];

        if (unlikely(NULL == nrt_ifp)) {
            ERR_SET_ERR(LUNE_ERR_ID_NOT_FOUND);
            return NULL;
        }

        if (!NET_IF_IS_NRT_ID_AGGR(id)) {
            /* single NA or single NP */
            if (core_id == nrt_ifp->non_aggr.core_id) {
                id = nrt_ifp->non_aggr.id;
                goto ID_FOUND;
            }

            /* interface not on current core */
            ERR_SET_ERR(LUNE_ERR_ID_NOT_FOUND);
            return NULL;
        }

        if (0 == nrt_ifp->aggr.aggr_num) {
            /* zero NA and multiple NP */
            for (i = 0; i < (int)nrt_ifp->aggr.chan_num; i++) {
                if (nrt_ifp->aggr.core_id_array[i] == core_id) {
                    break;
                }
            }

            if (i < (int)nrt_ifp->aggr.chan_num) {
                id = nrt_ifp->aggr.chan_id_array[i];
                goto ID_FOUND;
            }

            /* no interface created on current core for specified aggregated interface */
            ERR_SET_ERR(LUNE_ERR_ID_NOT_FOUND);
            return NULL;
        }

        if (1 == nrt_ifp->aggr.aggr_num) {
            /* single NA and single/multiple NP */
            if (nrt_ifp->aggr.core_id_array[0] == core_id) {
                /* single NA */
                id = nrt_ifp->aggr.aggr_id_array[0];
                goto ID_FOUND;
            }

            for (i = nrt_ifp->aggr.chan_num - 1, j = nrt_ifp->aggr.core_num - 1; i >= 0; i--, j--) {
                if (nrt_ifp->aggr.core_id_array[j] == core_id) {
                    break;
                }
            }

            if (i >= 0) {
                id = nrt_ifp->aggr.chan_id_array[i];
                goto ID_FOUND;
            }

            /* no interface created on current core for specified aggregated interface */
            ERR_SET_ERR(LUNE_ERR_ID_NOT_FOUND);
            return NULL;
        }

        /* multiple NA and multiple NP */
        for (i = 0; i < (int)nrt_ifp->aggr.aggr_num; i++) {
            if (nrt_ifp->aggr.core_id_array[i] == core_id) {
                break;
            }
        }

        if (i < (int)nrt_ifp->aggr.aggr_num) {
            id = nrt_ifp->aggr.aggr_id_array[i];
            goto ID_FOUND;
        }

        /*
            no aggregated interface created on current core for specified aggregated interface.
            continue searching for channel interface residing cores.
        */
        for (i = nrt_ifp->aggr.chan_num - 1, j = nrt_ifp->aggr.core_num - 1; i >= 0; i--, j--) {
            if (nrt_ifp->aggr.core_id_array[j] == core_id) {
                break;
            }
        }

        if (i >= 0) {
            id = nrt_ifp->aggr.chan_id_array[i];
            goto ID_FOUND;
        }

        /*
            no channel interface created on current core for specified aggregated interface either
        */
        ERR_SET_ERR(LUNE_ERR_ID_NOT_FOUND);
        return NULL;
    }

ID_FOUND:
    if (unlikely(id >= LUNE_NET_IF_MAX_NUM)) {
        ERR_SET_ERR(LUNE_ERR_NET_IF_INTERNAL);
        return NULL;
    }

    if (NULL == s_net_if_rt_array[id]) {
        return NULL;
    }

    return s_net_if_rt_array[id];
}

static net_if_t *net_if_get_net_if_by_name(lune_net_if_type_en type, const char *name)
{
    int i;
    net_if_t *ifp;

    for (i = 0; i < LUNE_NET_IF_MAX_NUM; i++) {
        ifp = s_net_if_rt_array[i];
        if (!strcmp(ifp->name, name)
            && ifp->type == type) {
            return ifp;
        }
    }

    return NULL;
}

static int net_if_del_net_if(net_if_t *ifp)
{
    int err;

    /*
        interface should be disabled first before it gets deleted
    */
    if (NET_IF_IS_ACTIVE(ifp)) {
        return ERR_SET_ERR(LUNE_ERR_NET_IF_ACTIVE);
    }

    if (NET_IF_IS_AGGR(ifp)) {
        lune_assert(NULL != ifp->aip);

        if (0 != (err = aggr_del_net_if(ifp->aip))) {
            return err;
        }

        ifp->aip = NULL;
        NET_IF_SET_NONAGGR(ifp);
    }

    if (NULL != ifp->drv->del_net_if) {
        if (0 != (err = ifp->drv->del_net_if(ifp->net_if_data))) {
            return err;
        }
    }

    s_net_if_rt_cnt--;
    lune_assert(s_net_if_rt_array[ifp->id] == ifp);
    s_net_if_rt_array[ifp->id] = NULL;

    net_if_put(ifp);

    return 0;
}

void net_if_recv_pkts_and_process(net_if_t *ifp)
{
    NET_IF_SET_CURR_NET_IF(ifp);
    (void)ifp->drv->recv_pkts(ifp->net_if_data);
    NET_IF_CLEAR_CURR_NET_IF();
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-qual"
static void net_if_recv_and_process(net_if_t *ifp)
{
    net_if_drv_t *drv = ifp->drv;
    unsigned char *buf;
    unsigned int len;
    int err, pkt_cnt = 0, max_pkt_cnt;
    pbuf_t pbuf;

    lune_assert(NET_IF_IS_ACTIVE(ifp));

    max_pkt_cnt = NET_IF_IS_AGGR(ifp) ? NET_IF_AGGR_MAX_RECV_PKT_NUM_PER_RECV_CALL
        : NET_IF_NON_AGGR_MAX_RECV_PKT_NUM_PER_RECV_CALL;

    NET_IF_SET_CURR_NET_IF(ifp);
    while (pkt_cnt < max_pkt_cnt) {
        if (0 != (err = drv->recv(ifp->net_if_data, (unsigned char **)&buf, &len))) {
            if (unlikely(err != -LUNE_ERR_NET_IF_NO_PKT)) {
                lune_log_once(LUNE_INFO, "failed to receive packet on interface %s: %s",
                    ifp->name, ERR_GET_ERR_STR(err));
            }

            break;
        }

        lune_assert(len > 0);

        pkt_cnt++;

        if (unlikely(NULL != ifp->hook.recv)
            && LUNE_NET_IF_HOOK_PKT_DROP == ifp->hook.recv(ifp->hook.data, buf, len)) {
            lune_assert(NET_IF_IS_HOOK(ifp));
            lune_assert(!NET_IF_IS_SOCKET(ifp));
            drv->recv_done(ifp->net_if_data);
            continue;
        }

        /* capture received packets if enabled */
        NET_IF_CAP_PKT(ifp, buf, len);

        if (NET_IF_IS_SOCKET(ifp)) {
            net_if_pcb_t *pcb;

            lune_assert(NULL != ifp->sk);
            pcb = &((socket_t *)ifp->sk)->pcb.net_if;
            if (unlikely(NULL == pcb->cb.recv)) {
                /*
                    once a socket is bound to a specific interface without setting
                    callback function, all packets on that interface will be simply
                    bypassed.
                */
            } else {
                SOCKET_PUSH_CB_SK(ifp->sk);
                (void)pcb->cb.recv(pcb->cb.data, buf, len);
                SOCKET_POP_CB_SK();
            }

            drv->recv_done(ifp->net_if_data);
            continue;
        }

        if (NET_IF_IS_AGGR(ifp)) {
            AGGR_SET_CURR_AGGR_NET_IF(ifp);
            (void)aggr_net_if_recv(ifp->aip, buf, len);
            AGGR_CLEAR_CURR_AGGR_NET_IF();
            continue;
        }

        pbuf_init_recv_pbuf(&pbuf, buf, len);

        (void)mac_input(ifp, LUNE_ID_NET_IF, &pbuf);

        drv->recv_done(ifp->net_if_data);

        /*
            MUST be called after mac_input() as all the info is filled
            during packet processing
        */
        switch (PBUF_GET_L4_TYPE(&pbuf)) {
        case PBUF_L4_TYPE_TCP:
            NET_IF_TCP_INC_PKT_IN(ifp);
            NET_IF_TCP_ADD_DATA_IN(ifp, pbuf.tcp.data_len);
            break;
        default:
            break;
        }
    }
    NET_IF_CLEAR_CURR_NET_IF();
}
#pragma GCC diagnostic pop

int net_if_process_single_net_if_recv_func(net_if_t *ifp,
    unsigned char *buf, unsigned int len, int skip_cap)
{
    int err;
    pbuf_t pbuf;

    if (unlikely(NULL != ifp->hook.recv)
        && LUNE_NET_IF_HOOK_PKT_DROP == ifp->hook.recv(ifp->hook.data, buf, len)) {
        lune_assert(NET_IF_IS_HOOK(ifp));
        lune_assert(!NET_IF_IS_SOCKET(ifp));
        ifp->drv->recv_done(ifp->net_if_data);
        return 0;
    }

    if (!skip_cap) {
        /* capture received packets if enabled */
        NET_IF_CAP_PKT(ifp, buf, len);
    }

    if (NET_IF_IS_SOCKET(ifp)) {
        net_if_pcb_t *pcb;

        lune_assert(NULL != ifp->sk);
        pcb = &((socket_t *)ifp->sk)->pcb.net_if;
        if (unlikely(NULL == pcb->cb.recv)) {
            /*
                once a socket is bound to a specific interface without setting
                callback function, all packets on that interface will be simply
                bypassed.
            */
            err = 0;
        } else {
            SOCKET_PUSH_CB_SK(ifp->sk);
            err = pcb->cb.recv(pcb->cb.data, buf, len);
            SOCKET_POP_CB_SK();
        }

        ifp->drv->recv_done(ifp->net_if_data);
        return err;
    }

    if (NET_IF_IS_AGGR(ifp)) {
        AGGR_SET_CURR_AGGR_NET_IF(ifp);
        err = aggr_net_if_recv(ifp->aip, buf, len);
        AGGR_CLEAR_CURR_AGGR_NET_IF();
        return err;
    }

    pbuf_init_recv_pbuf(&pbuf, buf, len);

    err = mac_input(ifp, LUNE_ID_NET_IF, &pbuf);

    ifp->drv->recv_done(ifp->net_if_data);

    /*
        MUST be called after mac_input() as all the info is filled
        during packet processing
    */
    switch (PBUF_GET_L4_TYPE(&pbuf)) {
    case PBUF_L4_TYPE_TCP:
        NET_IF_TCP_INC_PKT_IN(ifp);
        NET_IF_TCP_ADD_DATA_IN(ifp, pbuf.tcp.data_len);
        break;
    default:
        break;
    }

    return err;
}

static int net_if_enable_net_if(net_if_t *ifp)
{
    int err;

    if (NET_IF_IS_AGGR(ifp)) {
        if (0 != (err = aggr_enable_net_if(ifp->aip))) {
            goto ERR_1;
        }
    }

    if (NULL != ifp->drv->recv_pkts) {
        if (LUNE_INVALID_ID == (ifp->rx_task_id = sched_add_task(ifp->name,
            net_if_recv_pkts_and_process, (void *)ifp, SCHED_PRIO_RECV))) {
            goto ERR_2;
        }
    } else {
        if (LUNE_INVALID_ID == (ifp->rx_task_id = sched_add_task(ifp->name,
            net_if_recv_and_process, (void *)ifp, SCHED_PRIO_RECV))) {
            goto ERR_2;
        }
    }

    timer_add_timer(&ifp->stats_tmr, NET_IF_GET_STATS_INTVL);

    if (NULL != ifp->drv->is_up
        && unlikely(ifp->drv->is_up(ifp->net_if_data))) {
        /* it shouldn't be up till interface is enabled */
        lune_log(LUNE_WARN, "status already up on interface %s"
            " while enabling it", ifp->name);
        ERR_SET_ERR(LUNE_ERR_NET_IF_INTERNAL);
        goto ERR_3;
    }

    if (NULL != ifp->drv->set_up
        && ifp->drv->set_up(ifp->net_if_data)) {
        goto ERR_3;
    }

    timer_add_timer(&ifp->max_tx_data_rate_tmr, NET_IF_MAX_TX_DATA_RATE_TIMER_INTVL);

    NET_IF_SET_ACTIVE(ifp);

    return 0;

ERR_3:
    timer_del_timer(&ifp->stats_tmr);
    if (LUNE_INVALID_ID != ifp->rx_task_id) {
        lune_assert(!sched_del_task(ifp->rx_task_id));
    }

ERR_2:
    if (NET_IF_IS_AGGR(ifp)) {
        lune_assert(!aggr_disable_net_if(ifp->aip));
    }

ERR_1:
    return ERR_GET_LAST_ERR();
}

static void net_if_clear_net_if_stats(net_if_t *ifp)
{
    memset(&ifp->stats, 0x00, sizeof(lune_net_if_stats_t));
    memset(&ifp->tcp_stats, 0x00, sizeof(lune_net_if_tcp_stats_t));
    memset(&ifp->ssl_stats, 0x00, sizeof(lune_net_if_ssl_stats_t));
}

static int net_if_disable_net_if(net_if_t *ifp)
{
    int err;

    if (!NET_IF_IS_AGGR(ifp)) {
        if (NET_IF_IS_SOCKET(ifp)) {
            /*
                socket should be closed before interface being disabled
            */
            err = ERR_SET_ERR(LUNE_ERR_NOT_CLOSED);
            goto ERR_1;
        }
    } else {
        if (0 != (err = aggr_disable_net_if(ifp->aip))) {
            goto ERR_1;
        }
    }

    if (NULL != ifp->drv->is_up
        && unlikely(!ifp->drv->is_up(ifp->net_if_data))) {
        /* it shouldn't be down till interface is disabled */
        lune_log(LUNE_WARN, "status already down on interface %s"
            " while disabling it", ifp->name);
        ERR_SET_ERR(LUNE_ERR_NET_IF_INTERNAL);
        goto ERR_2;
    }

    if (NULL != ifp->drv->set_down
        && ifp->drv->set_down(ifp->net_if_data)) {
        lune_log(LUNE_WARN, "failed to set interface %s down"
            " while disabling it", ifp->name);
        err = ERR_SET_ERR(LUNE_ERR_NET_IF_INTERNAL);
        goto ERR_2;
    }

    timer_del_timer(&ifp->max_tx_data_rate_tmr);
    timer_del_timer(&ifp->stats_tmr);
    if (LUNE_INVALID_ID != ifp->rx_task_id) {
        lune_assert(!sched_del_task(ifp->rx_task_id));
    }

    if (NET_IF_IS_CAP_ENABLED(ifp)) {
        /*
            stop packet capture once interface disabled
        */
        cap_stop(ifp->cap_fp);
        ifp->cap_fp = NULL;
    }

    net_if_clear_net_if_stats(ifp);

    NET_IF_SET_INACTIVE(ifp);
    return 0;

ERR_2:
    if (NET_IF_IS_AGGR(ifp)) {
        lune_assert(!aggr_enable_net_if(ifp->aip));
    }

ERR_1:
    return err;
}

static unsigned int net_if_nrt_add_non_aggr_net_if(lune_net_if_type_en type,
    const char *name,
    const void *conf_val,
    unsigned int conf_len,
    unsigned int core_id,
    unsigned int is_aggr)
{
    unsigned int sleep_usecs = NET_IF_NRT_WAIT_RESP_SLEEP_USEC, len;
    net_if_comm_add_net_if_conf_t conf = {0};
    lune_comm_resp_type_en resp_type;
    unsigned int id;
    int err, rt_err = 0;
    net_if_nrt_net_if_t *nrt_ifp;

#ifdef LUNE_DEBUG
    lune_assert(!CORE_IS_RT_CORE());
#endif

    if (NULL == (nrt_ifp = lune_malloc_mt(sizeof(net_if_nrt_net_if_t)))) {
        lune_log(LUNE_INFO, "failed to create interface %s on core %d: %s",
            conf.name, core_id, ERR_GET_LAST_ERR_STR());
        goto ERR_1;
    }

    if (LUNE_INVALID_ID == (id = net_if_nrt_get_new_id())) {
        goto ERR_2;
    }
    nrt_ifp->nrt_id = NET_IF_CONV_NRT_INT_ID_TO_NRT_ID(id, 0);
    nrt_ifp->non_aggr.core_id = core_id;

    conf.type = type;
    strcpy(conf.name, name);
    if (NULL != conf_val) {
        memcpy(&conf.dpdk_conf, conf_val, conf_len);
    }
    conf.is_aggr = is_aggr;
    if (0 != (err = comm_send_req_to_core(core_id,
        LUNE_COMM_REQ_ADD_NET_IF,
        (const void *)&conf,
        sizeof(net_if_comm_add_net_if_conf_t)))) {
        lune_log(LUNE_INFO, "failed to send request of creating interface %s"
            " to core %d: %s", conf.name, core_id, ERR_GET_ERR_STR(err));
        goto ERR_2;
    }

    len = sizeof(unsigned int);
    while (-LUNE_ERR_BUF_EMPTY == (err = comm_recv_resp_from_core(core_id,
        &resp_type, &rt_err, (void **)&nrt_ifp->non_aggr.id, &len))) {
        usleep(sleep_usecs);
    }

    if (0 != rt_err) {
        err = rt_err;
        ERR_SET_ERR(-err);
    }

    if (0 != err) {
        lune_assert(0 == len);
        lune_log(LUNE_INFO, "failed to create interface %s on core %d: %s",
            conf.name, core_id, ERR_GET_ERR_STR(err));
        goto ERR_2;
    }

    lune_assert(len == sizeof(unsigned int));
    lune_assert(LUNE_COMM_RESP_ADD_NET_IF == resp_type);

    s_net_if_nrt_array[id] = nrt_ifp;
    s_net_if_nrt_cnt++;
    s_net_if_nrt_array_offset = ((id + 1) % LUNE_NET_IF_MAX_NUM);

    return nrt_ifp->nrt_id;

ERR_2:
    lune_free_mt(nrt_ifp);

ERR_1:
    return LUNE_INVALID_ID;
}

static int net_if_nrt_del_non_aggr_net_if(unsigned int id)
{
    unsigned int sleep_usecs = NET_IF_NRT_WAIT_RESP_SLEEP_USEC;
    lune_comm_resp_type_en resp_type;
    int err, rt_err = 0;
    net_if_nrt_net_if_t *nrt_ifp;
    net_if_comm_del_net_if_conf_t conf;

#ifdef LUNE_DEBUG
    lune_assert(!CORE_IS_RT_CORE());
#endif

    if (unlikely(NULL == (nrt_ifp = s_net_if_nrt_array[NET_IF_GET_NRT_INT_ID(id)]))) {
        return ERR_SET_ERR(LUNE_ERR_ID_NOT_FOUND);
    }

    conf.id = nrt_ifp->non_aggr.id;
    if (0 != (err = comm_send_req_to_core(nrt_ifp->non_aggr.core_id,
        LUNE_COMM_REQ_DEL_NET_IF,
        (const void *)&conf,
        sizeof(conf)))) {
        lune_log(LUNE_INFO, "failed to send request of deleting interface %08x"
            " to core %d: %s", id, nrt_ifp->non_aggr.core_id, ERR_GET_ERR_STR(err));
        if (-LUNE_ERR_CORE_NOT_RUNNING != err) {
            return err;
        }

        /*
            if core has been deleted, any interface on core has already been disabled and
            deleted before the core quits. just release resource
        */
        goto DELETED;
    }

    while (-LUNE_ERR_BUF_EMPTY == (err = comm_recv_resp_from_core(nrt_ifp->non_aggr.core_id,
        &resp_type, &rt_err, NULL, 0))) {
        usleep(sleep_usecs);
    }

    if (0 != rt_err) {
        err = rt_err;
        ERR_SET_ERR(-err);
    }

    if (0 != err) {
        lune_log(LUNE_INFO, "failed to delete interface %08x on core %d: %s",
            id, nrt_ifp->non_aggr.core_id, ERR_GET_ERR_STR(err));
        return err;
    }

    lune_assert(LUNE_COMM_RESP_DEL_NET_IF == resp_type);

DELETED:
    s_net_if_nrt_cnt--;
    s_net_if_nrt_array[NET_IF_GET_NRT_INT_ID(id)] = NULL;
    lune_free_mt(nrt_ifp);

    return 0;
}

static int net_if_nrt_enable_non_aggr_net_if(unsigned int id)
{
    unsigned int sleep_usecs = NET_IF_NRT_WAIT_RESP_SLEEP_USEC;
    lune_comm_resp_type_en resp_type;
    int err, rt_err = 0;
    net_if_nrt_net_if_t *nrt_ifp;
    net_if_comm_enable_net_if_conf_t conf;

#ifdef LUNE_DEBUG
    lune_assert(!CORE_IS_RT_CORE());
#endif

    if (unlikely(NULL == (nrt_ifp = s_net_if_nrt_array[NET_IF_GET_NRT_INT_ID(id)]))) {
        return ERR_SET_ERR(LUNE_ERR_ID_NOT_FOUND);
    }

    conf.id = nrt_ifp->non_aggr.id;
    if (0 != (err = comm_send_req_to_core(nrt_ifp->non_aggr.core_id,
        LUNE_COMM_REQ_ENABLE_NET_IF,
        (const void *)&conf,
        sizeof(conf)))) {
        lune_log(LUNE_INFO, "failed to send request of enabling interface %08x"
            " to core %d: %s", id, nrt_ifp->non_aggr.core_id, ERR_GET_ERR_STR(err));
        return err;
    }

    while (-LUNE_ERR_BUF_EMPTY == (err = comm_recv_resp_from_core(nrt_ifp->non_aggr.core_id,
        &resp_type, &rt_err, NULL, 0))) {
        usleep(sleep_usecs);
    }

    if (0 != rt_err) {
        err = rt_err;
        ERR_SET_ERR(-err);
    }

    if (0 != err) {
        lune_log(LUNE_INFO, "failed to enable interface %08x on core %d: %s",
            id, nrt_ifp->non_aggr.core_id, ERR_GET_ERR_STR(err));
        return err;
    }

    lune_assert(LUNE_COMM_RESP_ENABLE_NET_IF == resp_type);

    return 0;
}

static int net_if_nrt_disable_non_aggr_net_if(unsigned int id)
{
    unsigned int sleep_usecs = NET_IF_NRT_WAIT_RESP_SLEEP_USEC;
    lune_comm_resp_type_en resp_type;
    int err, rt_err = 0;
    net_if_nrt_net_if_t *nrt_ifp;
    net_if_comm_disable_net_if_conf_t conf;

#ifdef LUNE_DEBUG
    lune_assert(!CORE_IS_RT_CORE());
#endif

    if (unlikely(NULL == (nrt_ifp = s_net_if_nrt_array[NET_IF_GET_NRT_INT_ID(id)]))) {
        return ERR_SET_ERR(LUNE_ERR_ID_NOT_FOUND);
    }

    conf.id = nrt_ifp->non_aggr.id;
    if (0 != (err = comm_send_req_to_core(nrt_ifp->non_aggr.core_id,
        LUNE_COMM_REQ_DISABLE_NET_IF,
        (const void *)&conf,
        sizeof(conf)))) {
        lune_log(LUNE_INFO, "failed to send request of disabling interface %08x"
            " to core %d: %s", id, nrt_ifp->non_aggr.core_id, ERR_GET_ERR_STR(err));
        /*
            return success if core has been deleted, any interface on core has already been
            disabled and deleted before the core quits
        */
        return -LUNE_ERR_CORE_NOT_RUNNING == err ? 0 : err;
    }

    while (-LUNE_ERR_BUF_EMPTY == (err = comm_recv_resp_from_core(nrt_ifp->non_aggr.core_id,
        &resp_type, &rt_err, NULL, 0))) {
        usleep(sleep_usecs);
    }

    if (0 != rt_err) {
        err = rt_err;
        ERR_SET_ERR(-err);
    }

    if (0 != err) {
        lune_log(LUNE_INFO, "failed to disable interface %08x on core %d: %s",
            id, nrt_ifp->non_aggr.core_id, ERR_GET_ERR_STR(err));
        return err;
    }

    lune_assert(LUNE_COMM_RESP_DISABLE_NET_IF == resp_type);

    return 0;
}

static unsigned int net_if_nrt_add_dpdk_queue_net_if(const char *name,
    const lune_net_if_dpdk_queue_conf_t *dpdk_queue_conf,
    unsigned int core_num,
    cpu_bit_mask_t np_bit_mask)
{
    int err, rt_err = 0;
    unsigned int i, j, sleep_usecs = NET_IF_NRT_WAIT_RESP_SLEEP_USEC, len, id;
    net_if_comm_add_net_if_conf_t add_net_if_conf;
    lune_comm_resp_type_en resp_type;
    net_if_nrt_net_if_t *nrt_ifp;

#ifdef LUNE_DEBUG
    lune_assert(!CORE_IS_RT_CORE());
#endif

    if (NULL == (nrt_ifp = lune_malloc_mt(sizeof(net_if_nrt_net_if_t)))) {
        lune_log(LUNE_INFO, "failed to create interface %s: %s",
            name, ERR_GET_LAST_ERR_STR());
        goto ERR_1;
    }

    nrt_ifp->aggr.core_num = nrt_ifp->aggr.chan_num = core_num;
    nrt_ifp->aggr.aggr_num = 0;

    i = j = 0;
    while (j < core_num) {
        if (CPU_IS_BIT_SET(np_bit_mask, i)) {
            add_net_if_conf.type = LUNE_NET_IF_DPDK_QUEUE;
            sprintf(add_net_if_conf.name, "%s/%d", name, j);
            add_net_if_conf.is_aggr = 0;
            add_net_if_conf.dpdk_queue_conf.rxq_num = dpdk_queue_conf->rxq_num;
            add_net_if_conf.dpdk_queue_conf.txq_num = dpdk_queue_conf->txq_num;
            add_net_if_conf.dpdk_queue_conf.rss_type = dpdk_queue_conf->rss_type;
            if (0 != (err = comm_send_req_to_core(i,
                LUNE_COMM_REQ_ADD_NET_IF,
                (const void *)&add_net_if_conf,
                sizeof(net_if_comm_add_net_if_conf_t)))) {
                lune_log(LUNE_INFO, "failed to send request of creating interface %s"
                    " to core %d: %s", add_net_if_conf.name, i, ERR_GET_ERR_STR(err));
                goto ERR_2;
            }

            len = sizeof(unsigned int);
            while (-LUNE_ERR_BUF_EMPTY == (err = comm_recv_resp_from_core(i,
                &resp_type, &rt_err, &nrt_ifp->aggr.chan_id_array[j], &len))) {
                usleep(sleep_usecs);
            }

            if (0 != rt_err) {
                err = rt_err;
                ERR_SET_ERR(-err);
            }

            if (0 != err) {
                lune_log(LUNE_INFO, "failed to create interface %s on core %d: %s",
                    add_net_if_conf.name, i, ERR_GET_ERR_STR(err));
                goto ERR_2;
            }

            lune_assert(len == sizeof(unsigned int));
            lune_assert(LUNE_COMM_RESP_ADD_NET_IF == resp_type);

            nrt_ifp->aggr.core_id_array[j] = i;

            j++;
        }
        i++;
    }

    if (LUNE_INVALID_ID == (id = net_if_nrt_get_new_id())) {
        goto ERR_3;
    }
    s_net_if_nrt_array[id] = nrt_ifp;
    s_net_if_nrt_cnt++;
    s_net_if_nrt_array_offset = ((id + 1) % LUNE_NET_IF_MAX_NUM);

    return NET_IF_CONV_NRT_INT_ID_TO_NRT_ID(id, 1);

ERR_3:
    j = core_num;

ERR_2:
    for (i = 0; i < j; i++) {
        if (0 != (err = comm_send_req_to_core(nrt_ifp->aggr.core_id_array[i],
            LUNE_COMM_REQ_DEL_NET_IF,
            (const void *)&nrt_ifp->aggr.chan_id_array[i],
            sizeof(nrt_ifp->aggr.chan_id_array[i])))) {
            lune_log(LUNE_INFO, "failed to send request of deleting interface %08x to core %d: %s",
                nrt_ifp->aggr.chan_id_array[i], nrt_ifp->aggr.core_id_array[i], ERR_GET_ERR_STR(err));
            continue;
        }

        while (-LUNE_ERR_BUF_EMPTY == (err = comm_recv_resp_from_core(nrt_ifp->aggr.core_id_array[i],
            &resp_type, &rt_err, NULL, 0))) {
            usleep(sleep_usecs);
        }

        if (0 != rt_err) {
            err = rt_err;
            ERR_SET_ERR(-err);
        }

        if (0 != err) {
            lune_log(LUNE_INFO, "failed to delete interface %08x on core %d: %s",
                nrt_ifp->aggr.chan_id_array[i], nrt_ifp->aggr.core_id_array[i], ERR_GET_ERR_STR(err));
            continue;
        }
    }

    lune_free_mt(nrt_ifp);

ERR_1:
    return LUNE_INVALID_ID;
}

static unsigned int net_if_nrt_add_aggr_net_if(lune_net_if_type_en type,
    const char *name,
    const void *conf_val,
    unsigned int conf_len,
    const lune_net_if_nrt_aggr_conf_t *na_conf,
    unsigned int np_core_num,
    cpu_bit_mask_t bit_mask)
{
    int err, rt_err = 0;
    unsigned int i, j, na_id;
    unsigned int sleep_usecs = NET_IF_NRT_WAIT_RESP_SLEEP_USEC, len;
    net_if_comm_add_net_if_conf_t conf;
    lune_comm_resp_type_en resp_type;
    unsigned int id;
    net_if_nrt_net_if_t *nrt_ifp;

#ifdef LUNE_DEBUG
    lune_assert(!CORE_IS_RT_CORE());
#endif

    na_id = (unsigned int)cpu_get_first_core(bit_mask, CPU_CORE_RT_NA);

    if (NULL == (nrt_ifp = lune_malloc_mt(sizeof(net_if_nrt_net_if_t)))) {
        lune_log(LUNE_INFO, "failed to create interface %s on core %d: %s",
            conf.name, na_id, ERR_GET_LAST_ERR_STR());
        goto ERR_1;
    }

    conf.type = type;
    strcpy(conf.name, name);
    if (LUNE_NET_IF_DPDK == type) {
        memcpy(&conf.dpdk_conf, conf_val, conf_len);
    }
    memcpy(&conf.aggr_conf, &na_conf->conf, sizeof(lune_net_if_aggr_conf_t));
    conf.is_aggr = 1;
    if (0 != (err = comm_send_req_to_core(na_id,
        LUNE_COMM_REQ_ADD_NET_IF,
        (const void *)&conf,
        sizeof(net_if_comm_add_net_if_conf_t)))) {
        lune_log(LUNE_INFO, "failed to send request of creating interface %s"
            " to core %d: %s", conf.name, na_id, ERR_GET_ERR_STR(err));
        goto ERR_2;
    }

    len = sizeof(unsigned int);
    while (-LUNE_ERR_BUF_EMPTY == (err = comm_recv_resp_from_core(na_id,
        &resp_type, &rt_err, (void *)&nrt_ifp->aggr.aggr_id_array[0], &len))) {
        usleep(sleep_usecs);
    }

    if (0 != rt_err) {
        err = rt_err;
        ERR_SET_ERR(-err);
    }

    if (0 != err) {
        lune_log(LUNE_INFO, "failed to create interface %s on core %d: %s",
            conf.name, na_id, ERR_GET_ERR_STR(err));
        goto ERR_2;
    }

    lune_assert(len == sizeof(unsigned int));
    lune_assert(LUNE_COMM_RESP_ADD_NET_IF == resp_type);

    nrt_ifp->aggr.core_id_array[0] = na_id;

    lune_assert(!cpu_get_core_bit_mask(&bit_mask, CPU_CORE_RT_NP));

    i = j = 0;
    while (j < np_core_num) {
        if (CPU_IS_BIT_SET(bit_mask, i)) {
            conf.type = na_conf->chan_type;
            sprintf(conf.name, "%s/%d", name, j);
            conf.is_aggr = 0;
            if (0 != (err = comm_send_req_to_core(i,
                LUNE_COMM_REQ_ADD_NET_IF,
                (const void *)&conf,
                sizeof(net_if_comm_add_net_if_conf_t)))) {
                lune_log(LUNE_INFO, "failed to send request of creating interface %s"
                    " to core %d: %s", conf.name, i, ERR_GET_ERR_STR(err));
                goto ERR_3;
            }

            len = sizeof(unsigned int);
            while (-LUNE_ERR_BUF_EMPTY == (err = comm_recv_resp_from_core(i,
                &resp_type, &rt_err, &nrt_ifp->aggr.chan_id_array[j], &len))) {
                usleep(sleep_usecs);
            }

            if (0 != rt_err) {
                err = rt_err;
                ERR_SET_ERR(-err);
            }

            if (0 != err) {
                lune_log(LUNE_INFO, "failed to create interface %s on core %d: %s",
                    conf.name, i, ERR_GET_ERR_STR(err));
                goto ERR_3;
            }

            lune_assert(len == sizeof(unsigned int));
            lune_assert(LUNE_COMM_RESP_ADD_NET_IF == resp_type);

            nrt_ifp->aggr.core_id_array[j + 1] = i;

            j++;
        }

        i++;
    }

    nrt_ifp->aggr.chan_num = np_core_num;
    nrt_ifp->aggr.aggr_num = 1;
    nrt_ifp->aggr.core_num = np_core_num + 1;
    if (LUNE_INVALID_ID == (id = net_if_nrt_get_new_id())) {
        goto ERR_3;
    }
    s_net_if_nrt_array[id] = nrt_ifp;
    s_net_if_nrt_cnt++;
    s_net_if_nrt_array_offset = ((id + 1) % LUNE_NET_IF_MAX_NUM);

    return NET_IF_CONV_NRT_INT_ID_TO_NRT_ID(id, 1);

ERR_3:
    for (i = 1; i <= j; i++) {
        if (0 != (err = comm_send_req_to_core(nrt_ifp->aggr.core_id_array[i],
            LUNE_COMM_REQ_DEL_NET_IF,
            (const void *)&nrt_ifp->aggr.chan_id_array[i],
            sizeof(nrt_ifp->aggr.chan_id_array[i])))) {
            lune_log(LUNE_INFO, "failed to send request of deleting interface %08x to core %d: %s",
                nrt_ifp->aggr.chan_id_array[i], nrt_ifp->aggr.core_id_array[i], ERR_GET_ERR_STR(err));
            continue;
        }

        while (-LUNE_ERR_BUF_EMPTY == (err = comm_recv_resp_from_core(nrt_ifp->aggr.core_id_array[i],
            &resp_type, &rt_err, NULL, 0))) {
            usleep(sleep_usecs);
        }

        if (0 != rt_err) {
            err = rt_err;
            ERR_SET_ERR(-err);
        }

        if (0 != err) {
            lune_log(LUNE_INFO, "failed to delete interface %08x on core %d: %s",
                nrt_ifp->aggr.chan_id_array[i], nrt_ifp->aggr.core_id_array[i], ERR_GET_ERR_STR(err));
            continue;
        }
    }

    if (0 != (err = comm_send_req_to_core(na_id,
        LUNE_COMM_REQ_DEL_NET_IF,
        (const void *)&nrt_ifp->aggr.aggr_id_array[0],
        sizeof(nrt_ifp->aggr.aggr_id_array[0])))) {
        lune_log(LUNE_INFO, "failed to send request of deleting interface %08x"
            " to core %d: %s", nrt_ifp->aggr.aggr_id_array[0], na_id, ERR_GET_ERR_STR(err));
        return LUNE_INVALID_ID;
    }

    while (-LUNE_ERR_BUF_EMPTY == (err = comm_recv_resp_from_core(na_id,
        &resp_type, &rt_err, NULL, 0))) {
        usleep(sleep_usecs);
    }

    if (0 != rt_err) {
        err = rt_err;
        ERR_SET_ERR(-err);
    }

    if (0 != err) {
        lune_log(LUNE_INFO, "failed to delete interface %08x on core %d: %s",
            nrt_ifp->aggr.aggr_id_array[0], na_id, ERR_GET_ERR_STR(err));
    }

ERR_2:
    lune_free_mt(nrt_ifp);

ERR_1:
    return LUNE_INVALID_ID;
}

static unsigned int net_if_nrt_add_aggr_dpdk_queue_net_if(const char *name,
    const lune_net_if_dpdk_queue_conf_t *dpdk_queue_conf,
    const lune_net_if_nrt_aggr_conf_t *aggr_conf,
    unsigned int na_core_num,
    unsigned int np_core_num,
    cpu_bit_mask_t na_bit_mask,
    cpu_bit_mask_t np_bit_mask)
{
    int err, rt_err = 0;
    unsigned int i, j, k, sleep_usecs = NET_IF_NRT_WAIT_RESP_SLEEP_USEC, len;
    net_if_comm_add_net_if_conf_t add_net_if_conf;
    lune_comm_resp_type_en resp_type;
    unsigned int id, np_per_na;
    net_if_nrt_net_if_t *nrt_ifp;
    unsigned long long start_mac_ll;

#ifdef LUNE_DEBUG
    lune_assert(!CORE_IS_RT_CORE());
#endif

    if (NULL == (nrt_ifp = lune_malloc_mt(sizeof(net_if_nrt_net_if_t)))) {
        lune_log(LUNE_INFO, "failed to create interface %s: %s",
            name, ERR_GET_LAST_ERR_STR());
        goto ERR_1;
    }

    nrt_ifp->aggr.core_num = na_core_num + np_core_num;
    nrt_ifp->aggr.chan_num = np_core_num;
    nrt_ifp->aggr.aggr_num = na_core_num;

    np_per_na = np_core_num / na_core_num;
    i = j = 0;
    while (j < na_core_num) {
        if (CPU_IS_BIT_SET(na_bit_mask, i)) {
            add_net_if_conf.type = LUNE_NET_IF_DPDK_QUEUE;
            sprintf(add_net_if_conf.name, "%s/%d", name, j);
            add_net_if_conf.aggr_conf.chan_num = np_per_na;
            add_net_if_conf.aggr_conf.type = aggr_conf->conf.type;
            switch (aggr_conf->conf.type) {
            case LUNE_NET_IF_AGGR_MAC_CLIENT:
            case LUNE_NET_IF_AGGR_MAC_SERVER:
                if (LUNE_NET_IF_CHAN == aggr_conf->chan_type) {
                    LUNE_MAC_TO_LL(aggr_conf->conf.mac.start_mac, start_mac_ll);
                    start_mac_ll += (j * aggr_conf->conf.mac.step);
                    LUNE_LL_TO_MAC(start_mac_ll, add_net_if_conf.aggr_conf.mac.start_mac);
                    LUNE_MAC_CPY(add_net_if_conf.aggr_conf.mac.end_mac, aggr_conf->conf.mac.end_mac);
                    add_net_if_conf.aggr_conf.mac.step = aggr_conf->conf.mac.step * na_core_num;
#ifdef LUNE_BUILD_DPDK
                } else {
                    lune_assert(LUNE_NET_IF_DPDK_QUEUE_CHAN == aggr_conf->chan_type);
                    LUNE_MAC_CPY(add_net_if_conf.aggr_conf.mac.start_mac, aggr_conf->conf.mac.start_mac);
                    LUNE_MAC_CPY(add_net_if_conf.aggr_conf.mac.end_mac, aggr_conf->conf.mac.end_mac);
                    add_net_if_conf.aggr_conf.mac.step = aggr_conf->conf.mac.step;
#endif
                }
                break;
            case LUNE_NET_IF_AGGR_IP_CLIENT:
            case LUNE_NET_IF_AGGR_IP_SERVER:
                if (aggr_conf->conf.ip.start_ip.is_ipv6) {
                    ERR_SET_ERR(LUNE_ERR_NOT_SUPPORTED);
                    goto ERR_2;
                }
                if (LUNE_NET_IF_CHAN == aggr_conf->chan_type) {
                    LUNE_IP_CPY(&add_net_if_conf.aggr_conf.ip.start_ip, &aggr_conf->conf.ip.start_ip);
                    add_net_if_conf.aggr_conf.ip.start_ip.ipv4 += (j * aggr_conf->conf.ip.step);
                    LUNE_IP_CPY(&add_net_if_conf.aggr_conf.ip.end_ip, &aggr_conf->conf.ip.end_ip);
                    add_net_if_conf.aggr_conf.ip.step = aggr_conf->conf.ip.step * na_core_num;
#ifdef LUNE_BUILD_DPDK
                } else {
                    LUNE_IP_CPY(&add_net_if_conf.aggr_conf.ip.start_ip, &aggr_conf->conf.ip.start_ip);
                    LUNE_IP_CPY(&add_net_if_conf.aggr_conf.ip.end_ip, &aggr_conf->conf.ip.end_ip);
                    add_net_if_conf.aggr_conf.ip.step = aggr_conf->conf.ip.step;
#endif
                }
                break;
            case LUNE_NET_IF_AGGR_CUSTOM:
                memcpy(&add_net_if_conf.aggr_conf.cust,
                    &aggr_conf->conf.cust, sizeof(aggr_conf->conf.cust));
                break;
            default:
                err = ERR_SET_ERR(LUNE_ERR_INTERNAL);
                goto ERR_2;
            }
            add_net_if_conf.is_aggr = 1;
            add_net_if_conf.dpdk_queue_conf.rxq_num = dpdk_queue_conf->rxq_num;
            add_net_if_conf.dpdk_queue_conf.txq_num = dpdk_queue_conf->txq_num;
            add_net_if_conf.dpdk_queue_conf.rss_type = dpdk_queue_conf->rss_type;
            if (0 != (err = comm_send_req_to_core(i,
                LUNE_COMM_REQ_ADD_NET_IF,
                (const void *)&add_net_if_conf,
                sizeof(net_if_comm_add_net_if_conf_t)))) {
                lune_log(LUNE_INFO, "failed to send request of creating interface %s"
                    " to core %d: %s", add_net_if_conf.name, i, ERR_GET_ERR_STR(err));
                goto ERR_2;
            }

            len = sizeof(unsigned int);
            while (-LUNE_ERR_BUF_EMPTY == (err = comm_recv_resp_from_core(i,
                &resp_type, &rt_err, &nrt_ifp->aggr.aggr_id_array[j], &len))) {
                usleep(sleep_usecs);
            }

            if (0 != rt_err) {
                err = rt_err;
                ERR_SET_ERR(-err);
            }

            if (0 != err) {
                lune_log(LUNE_INFO, "failed to create interface %s on core %d: %s",
                    add_net_if_conf.name, i, ERR_GET_ERR_STR(err));
                goto ERR_2;
            }

            lune_assert(len == sizeof(unsigned int));
            lune_assert(LUNE_COMM_RESP_ADD_NET_IF == resp_type);

            nrt_ifp->aggr.core_id_array[j] = i;

            j++;
        }
        i++;
    }

    i = j = 0;
    while (j < np_core_num) {
        if (CPU_IS_BIT_SET(np_bit_mask, i)) {
            add_net_if_conf.type = aggr_conf->chan_type;
            sprintf(add_net_if_conf.name, "%s/%d/%d", name, j / np_per_na, j % np_per_na);
            add_net_if_conf.is_aggr = 0;
            if (0 != (err = comm_send_req_to_core(i,
                LUNE_COMM_REQ_ADD_NET_IF,
                (const void *)&add_net_if_conf,
                sizeof(net_if_comm_add_net_if_conf_t)))) {
                lune_log(LUNE_INFO, "failed to send request of creating interface %s"
                    " to core %d: %s", add_net_if_conf.name, i, ERR_GET_ERR_STR(err));
                goto ERR_3;
            }

            len = sizeof(unsigned int);
            while (-LUNE_ERR_BUF_EMPTY == (err = comm_recv_resp_from_core(i,
                &resp_type, &rt_err, &nrt_ifp->aggr.chan_id_array[j], &len))) {
                usleep(sleep_usecs);
            }

            if (0 != rt_err) {
                err = rt_err;
                ERR_SET_ERR(-err);
            }

            if (0 != err) {
                lune_log(LUNE_INFO, "failed to create interface %s on core %d: %s",
                    add_net_if_conf.name, i, ERR_GET_ERR_STR(err));
                goto ERR_3;
            }

            lune_assert(len == sizeof(unsigned int));
            lune_assert(LUNE_COMM_RESP_ADD_NET_IF == resp_type);

            nrt_ifp->aggr.core_id_array[j + na_core_num] = i;

            j++;
        }
        i++;
    }

    if (LUNE_INVALID_ID == (id = net_if_nrt_get_new_id())) {
        goto ERR_3;
    }
    s_net_if_nrt_array[id] = nrt_ifp;
    s_net_if_nrt_cnt++;
    s_net_if_nrt_array_offset = ((id + 1) % LUNE_NET_IF_MAX_NUM);

    return NET_IF_CONV_NRT_INT_ID_TO_NRT_ID(id, 1);

ERR_3:
    for (i = 0; i < j; i++) {
        k = i + na_core_num;
        if (0 != (err = comm_send_req_to_core(nrt_ifp->aggr.core_id_array[k],
            LUNE_COMM_REQ_DEL_NET_IF,
            (const void *)&nrt_ifp->aggr.chan_id_array[i],
            sizeof(nrt_ifp->aggr.chan_id_array[i])))) {
            lune_log(LUNE_INFO, "failed to send request of deleting interface %08x to core %d: %s",
                nrt_ifp->aggr.chan_id_array[i], nrt_ifp->aggr.core_id_array[k], ERR_GET_ERR_STR(err));
            continue;
        }

        while (-LUNE_ERR_BUF_EMPTY == (err = comm_recv_resp_from_core(nrt_ifp->aggr.core_id_array[k],
            &resp_type, &rt_err, NULL, 0))) {
            usleep(sleep_usecs);
        }

        if (0 != rt_err) {
            err = rt_err;
            ERR_SET_ERR(-err);
        }

        if (0 != err) {
            lune_log(LUNE_INFO, "failed to delete interface %08x on core %d: %s",
                nrt_ifp->aggr.chan_id_array[i], nrt_ifp->aggr.core_id_array[k], ERR_GET_ERR_STR(err));
            continue;
        }
    }

    j = na_core_num;

ERR_2:
    for (i = 0; i < j; i++) {
        if (0 != (err = comm_send_req_to_core(nrt_ifp->aggr.core_id_array[i],
            LUNE_COMM_REQ_DEL_NET_IF,
            (const void *)&nrt_ifp->aggr.chan_id_array[i],
            sizeof(nrt_ifp->aggr.chan_id_array[i])))) {
            lune_log(LUNE_INFO, "failed to send request of deleting interface %08x to core %d: %s",
                nrt_ifp->aggr.chan_id_array[i], nrt_ifp->aggr.core_id_array[i], ERR_GET_ERR_STR(err));
            continue;
        }

        while (-LUNE_ERR_BUF_EMPTY == (err = comm_recv_resp_from_core(nrt_ifp->aggr.core_id_array[i],
            &resp_type, &rt_err, NULL, 0))) {
            usleep(sleep_usecs);
        }

        if (0 != rt_err) {
            err = rt_err;
            ERR_SET_ERR(-err);
        }

        if (0 != err) {
            lune_log(LUNE_INFO, "failed to delete interface %08x on core %d: %s",
                nrt_ifp->aggr.chan_id_array[i], nrt_ifp->aggr.core_id_array[i], ERR_GET_ERR_STR(err));
            continue;
        }
    }

    lune_free_mt(nrt_ifp);

ERR_1:
    return LUNE_INVALID_ID;
}

static int net_if_nrt_del_aggr_net_if(unsigned int id)
{
    int err, rt_err = 0;
    unsigned int i, j, sleep_usecs = NET_IF_NRT_WAIT_RESP_SLEEP_USEC;
    lune_comm_resp_type_en resp_type;
    net_if_nrt_net_if_t *nrt_ifp;
    net_if_comm_del_net_if_conf_t conf;

#ifdef LUNE_DEBUG
    lune_assert(!CORE_IS_RT_CORE());
#endif

    if (unlikely(NULL == (nrt_ifp = s_net_if_nrt_array[NET_IF_GET_NRT_INT_ID(id)]))) {
        return ERR_SET_ERR(LUNE_ERR_ID_NOT_FOUND);
    }

    for (i = 0; i < nrt_ifp->aggr.chan_num; i++) {
        conf.id = nrt_ifp->aggr.chan_id_array[i];
        j = i + nrt_ifp->aggr.aggr_num;
        if (0 != (err = comm_send_req_to_core(nrt_ifp->aggr.core_id_array[j],
            LUNE_COMM_REQ_DEL_NET_IF,
            (const void *)&conf,
            sizeof(conf)))) {
            lune_log(LUNE_INFO, "failed to send request of deleting interface %08x to core %d: %s",
                nrt_ifp->aggr.chan_id_array[i], nrt_ifp->aggr.core_id_array[j], ERR_GET_ERR_STR(err));
            continue;
        }

        while (-LUNE_ERR_BUF_EMPTY == (err = comm_recv_resp_from_core(nrt_ifp->aggr.core_id_array[j],
            &resp_type, &rt_err, NULL, 0))) {
            usleep(sleep_usecs);
        }

        if (0 != rt_err) {
            err = rt_err;
            ERR_SET_ERR(-err);
        }

        if (0 != err) {
            lune_log(LUNE_INFO, "failed to delete interface %08x on core %d: %s",
                nrt_ifp->aggr.chan_id_array[i], nrt_ifp->aggr.core_id_array[j], ERR_GET_ERR_STR(err));
            continue;
        }

        lune_assert(LUNE_COMM_RESP_DEL_NET_IF == resp_type);
    }

    if (0 == nrt_ifp->aggr.aggr_num) {
        /* zero NA and multiple NP */
        s_net_if_nrt_cnt--;
        s_net_if_nrt_array[NET_IF_GET_NRT_INT_ID(id)] = NULL;
        lune_free_mt(nrt_ifp);
        return 0;
    }

    for (i = 0; i < nrt_ifp->aggr.aggr_num; i++) {
        conf.id = nrt_ifp->aggr.aggr_id_array[i];
        if (0 != (err = comm_send_req_to_core(nrt_ifp->aggr.core_id_array[i],
            LUNE_COMM_REQ_DEL_NET_IF,
            (const void *)&conf,
            sizeof(conf)))) {
            lune_log(LUNE_INFO, "failed to send request of deleting interface %08x"
                " to core %d: %s", conf.id, nrt_ifp->aggr.core_id_array[i], ERR_GET_ERR_STR(err));
            continue;
        }

        while (-LUNE_ERR_BUF_EMPTY == (err = comm_recv_resp_from_core(nrt_ifp->aggr.core_id_array[i],
            &resp_type, &rt_err, NULL, 0))) {
            usleep(sleep_usecs);
        }

        if (0 != rt_err) {
            err = rt_err;
            ERR_SET_ERR(-err);
        }

        if (0 != err) {
            lune_log(LUNE_INFO, "failed to delete interface %08x on core %d: %s",
                conf.id, nrt_ifp->aggr.core_id_array[i], ERR_GET_ERR_STR(err));
        }

        lune_assert(LUNE_COMM_RESP_DEL_NET_IF == resp_type);
    }

    if (0 == err) {
        s_net_if_nrt_cnt--;
        s_net_if_nrt_array[NET_IF_GET_NRT_INT_ID(id)] = NULL;
        lune_free_mt(nrt_ifp);
    }

    return err;
}

static int net_if_nrt_enable_aggr_net_if(unsigned int id)
{
    int err, err2, rt_err = 0;
    unsigned int i, j, k, sleep_usecs = NET_IF_NRT_WAIT_RESP_SLEEP_USEC;
    lune_comm_resp_type_en resp_type;
    net_if_nrt_net_if_t *nrt_ifp;
    net_if_comm_enable_net_if_conf_t conf;

#ifdef LUNE_DEBUG
    lune_assert(!CORE_IS_RT_CORE());
#endif

    if (unlikely(NULL == (nrt_ifp = s_net_if_nrt_array[NET_IF_GET_NRT_INT_ID(id)]))) {
        err = ERR_SET_ERR(LUNE_ERR_ID_NOT_FOUND);
        goto ERR_1;
    }

    for (i = 0; i < nrt_ifp->aggr.aggr_num; i++) {
        conf.id = nrt_ifp->aggr.aggr_id_array[i];
        if (0 != (err = comm_send_req_to_core(nrt_ifp->aggr.core_id_array[i],
            LUNE_COMM_REQ_ENABLE_NET_IF,
            (const void *)&conf,
            sizeof(conf)))) {
            lune_log(LUNE_INFO, "failed to send request of enabling interface %08x"
                " to core %d: %s", conf.id, nrt_ifp->aggr.core_id_array[i], ERR_GET_ERR_STR(err));
            goto ERR_2;
        }

        while (-LUNE_ERR_BUF_EMPTY == (err = comm_recv_resp_from_core(nrt_ifp->aggr.core_id_array[i],
            &resp_type, &rt_err, NULL, 0))) {
            usleep(sleep_usecs);
        }

        if (0 != rt_err) {
            err = rt_err;
            ERR_SET_ERR(-err);
        }

        if (0 != err) {
            lune_log(LUNE_INFO, "failed to enable interface %08x on core %d: %s",
                conf.id, nrt_ifp->aggr.core_id_array[i], ERR_GET_ERR_STR(err));
            goto ERR_2;
        }

        lune_assert(LUNE_COMM_RESP_ENABLE_NET_IF == resp_type);
    }

    for (i = 0; i < nrt_ifp->aggr.chan_num; i++) {
        conf.id = nrt_ifp->aggr.chan_id_array[i];
        j = i + nrt_ifp->aggr.aggr_num;
        if (0 != (err = comm_send_req_to_core(nrt_ifp->aggr.core_id_array[j],
            LUNE_COMM_REQ_ENABLE_NET_IF,
            (const void *)&conf,
            sizeof(conf)))) {
            lune_log(LUNE_INFO, "failed to send request of enabling interface %08x to core %d: %s",
                nrt_ifp->aggr.chan_id_array[i], nrt_ifp->aggr.core_id_array[j], ERR_GET_ERR_STR(err));
            goto ERR_3;
        }

        while (-LUNE_ERR_BUF_EMPTY == (err = comm_recv_resp_from_core(nrt_ifp->aggr.core_id_array[j],
            &resp_type, &rt_err, NULL, 0))) {
            usleep(sleep_usecs);
        }

        if (0 != rt_err) {
            err = rt_err;
            ERR_SET_ERR(-err);
        }

        if (0 != err) {
            lune_log(LUNE_INFO, "failed to enable interface %08x on core %d: %s",
                nrt_ifp->aggr.chan_id_array[i], nrt_ifp->aggr.core_id_array[j], ERR_GET_ERR_STR(err));
            goto ERR_3;
        }

        lune_assert(LUNE_COMM_RESP_ENABLE_NET_IF == resp_type);
    }

    return 0;

ERR_3:
    for (j = 0; j < i; j++) {
        conf.id = nrt_ifp->aggr.chan_id_array[j];
        k = j + nrt_ifp->aggr.aggr_num;
        if (0 != (err2 = comm_send_req_to_core(nrt_ifp->aggr.core_id_array[k],
            LUNE_COMM_REQ_DISABLE_NET_IF,
            (const void *)&conf,
            sizeof(conf)))) {
            lune_log(LUNE_INFO, "failed to send request of disabling interface %08x to core %d: %s",
                nrt_ifp->aggr.chan_id_array[j], nrt_ifp->aggr.core_id_array[k], ERR_GET_ERR_STR(err2));
            continue;
        }

        while (-LUNE_ERR_BUF_EMPTY == (err2 = comm_recv_resp_from_core(nrt_ifp->aggr.core_id_array[k],
            &resp_type, &rt_err, NULL, 0))) {
            usleep(sleep_usecs);
        }

        if (0 != rt_err) {
            err2 = rt_err;
            ERR_SET_ERR(-err2);
        }

        if (0 != err2) {
            lune_log(LUNE_INFO, "failed to disable interface %08x on core %d: %s",
                nrt_ifp->aggr.chan_id_array[j], nrt_ifp->aggr.core_id_array[k], ERR_GET_ERR_STR(err2));
            continue;
        }

        lune_assert(LUNE_COMM_RESP_DISABLE_NET_IF == resp_type);
    }

    i = nrt_ifp->aggr.aggr_num;

ERR_2:
    for (j = 0; j < i; j++) {
        conf.id = nrt_ifp->aggr.aggr_id_array[j];
        if (0 != (err2 = comm_send_req_to_core(nrt_ifp->aggr.core_id_array[j],
            LUNE_COMM_REQ_DISABLE_NET_IF,
            (const void *)&conf,
            sizeof(conf)))) {
            lune_log(LUNE_INFO, "failed to send request of disabling interface %08x to core %d: %s",
                nrt_ifp->aggr.aggr_id_array[j], nrt_ifp->aggr.core_id_array[j], ERR_GET_ERR_STR(err2));
            continue;
        }

        while (-LUNE_ERR_BUF_EMPTY == comm_recv_resp_from_core(nrt_ifp->aggr.core_id_array[j],
            &resp_type, &rt_err, NULL, 0)) {
            usleep(sleep_usecs);
        }

        if (0 != rt_err) {
            err2 = rt_err;
            ERR_SET_ERR(-err2);
        }

        if (0 != err2) {
            lune_log(LUNE_INFO, "failed to disable interface %08x on core %d: %s",
                nrt_ifp->aggr.aggr_id_array[j], nrt_ifp->aggr.core_id_array[j], ERR_GET_ERR_STR(err2));
            continue;
        }

        lune_assert(LUNE_COMM_RESP_DISABLE_NET_IF == resp_type);
    }

ERR_1:
    return err;
}

static int net_if_nrt_disable_aggr_net_if(unsigned int id)
{
    int err, err2, rt_err = 0;
    unsigned int i, j, k, sleep_usecs = NET_IF_NRT_WAIT_RESP_SLEEP_USEC;
    lune_comm_resp_type_en resp_type;
    net_if_nrt_net_if_t *nrt_ifp;
    net_if_comm_disable_net_if_conf_t conf;

#ifdef LUNE_DEBUG
    lune_assert(!CORE_IS_RT_CORE());
#endif

    if (unlikely(NULL == (nrt_ifp = s_net_if_nrt_array[NET_IF_GET_NRT_INT_ID(id)]))) {
        err = ERR_SET_ERR(LUNE_ERR_ID_NOT_FOUND);
        goto ERR_1;
    }

    for (i = 0; i < nrt_ifp->aggr.chan_num; i++) {
        conf.id = nrt_ifp->aggr.chan_id_array[i];
        j = i + nrt_ifp->aggr.aggr_num;
        if (0 != (err = comm_send_req_to_core(nrt_ifp->aggr.core_id_array[j],
            LUNE_COMM_REQ_DISABLE_NET_IF,
            (const void *)&conf,
            sizeof(conf)))) {
            lune_log(LUNE_INFO, "failed to send request of disabling interface %08x to core %d: %s",
                nrt_ifp->aggr.chan_id_array[i], nrt_ifp->aggr.core_id_array[j], ERR_GET_ERR_STR(err));

            if (-LUNE_ERR_CORE_NOT_RUNNING != err) {
                goto ERR_3;
            }
    
            /*
                if core has been deleted, any interface on core has already been disabled and
                deleted before the core quits. just continue
            */
            continue;
        }

        while (-LUNE_ERR_BUF_EMPTY == (err = comm_recv_resp_from_core(nrt_ifp->aggr.core_id_array[j],
            &resp_type, &rt_err, NULL, 0))) {
            usleep(sleep_usecs);
        }

        if (0 != rt_err) {
            err = rt_err;
            ERR_SET_ERR(-err);
        }

        if (0 != err) {
            lune_log(LUNE_INFO, "failed to disable interface %08x on core %d: %s",
                nrt_ifp->aggr.chan_id_array[i], nrt_ifp->aggr.core_id_array[j], ERR_GET_ERR_STR(err));
            goto ERR_2;
        }

        lune_assert(LUNE_COMM_RESP_DISABLE_NET_IF == resp_type);
    }

    for (i = 0; i < nrt_ifp->aggr.aggr_num; i++) {
        conf.id = nrt_ifp->aggr.aggr_id_array[i];
        if (0 != (err = comm_send_req_to_core(nrt_ifp->aggr.core_id_array[i],
            LUNE_COMM_REQ_DISABLE_NET_IF,
            (const void *)&conf,
            sizeof(conf)))) {
            lune_log(LUNE_INFO, "failed to send request of disable interface %08x"
                " to core %d: %s", conf.id, nrt_ifp->aggr.core_id_array[i], ERR_GET_ERR_STR(err));

            if (-LUNE_ERR_CORE_NOT_RUNNING != err) {
                goto ERR_3;
            }
    
            /*
                if core has been deleted, any interface on core has already been disabled and
                deleted before the core quits. just continue
            */
            continue;
        }

        while (-LUNE_ERR_BUF_EMPTY == (err = comm_recv_resp_from_core(nrt_ifp->aggr.core_id_array[i],
            &resp_type, &rt_err, NULL, 0))) {
            usleep(sleep_usecs);
        }

        if (0 != rt_err) {
            err = rt_err;
            ERR_SET_ERR(-err);
        }

        if (0 != err) {
            lune_log(LUNE_INFO, "failed to disable interface %08x on core %d: %s",
                conf.id, nrt_ifp->aggr.core_id_array[i], ERR_GET_ERR_STR(err));
            goto ERR_3;
        }

        lune_assert(LUNE_COMM_RESP_DISABLE_NET_IF == resp_type);
    }

    return 0;

ERR_3:
    for (j = 0; j < i; j++) {
        conf.id = nrt_ifp->aggr.aggr_id_array[j];
        if (0 != (err2 = comm_send_req_to_core(nrt_ifp->aggr.core_id_array[j],
            LUNE_COMM_REQ_ENABLE_NET_IF,
            (const void *)&conf,
            sizeof(conf)))) {
            lune_log(LUNE_INFO, "failed to send request of enabling interface %08x to core %d: %s",
                nrt_ifp->aggr.aggr_id_array[j], nrt_ifp->aggr.core_id_array[j], ERR_GET_ERR_STR(err2));
            continue;
        }

        while (-LUNE_ERR_BUF_EMPTY == (err2 = comm_recv_resp_from_core(nrt_ifp->aggr.core_id_array[j],
            &resp_type, &rt_err, NULL, 0))) {
            usleep(sleep_usecs);
        }

        if (0 != rt_err) {
            err2 = rt_err;
            ERR_SET_ERR(-err2);
        }

        if (0 != err2) {
            lune_log(LUNE_INFO, "failed to enable interface %08x on core %d: %s",
                nrt_ifp->aggr.aggr_id_array[j], nrt_ifp->aggr.core_id_array[j], ERR_GET_ERR_STR(err2));
            continue;
        }

        lune_assert(LUNE_COMM_RESP_ENABLE_NET_IF == resp_type);
    }

    i = nrt_ifp->aggr.chan_num;

ERR_2:
    for (j = 0; j < i; j++) {
        conf.id = nrt_ifp->aggr.chan_id_array[j];
        k = j + nrt_ifp->aggr.aggr_num;
        if (0 != (err2 = comm_send_req_to_core(nrt_ifp->aggr.core_id_array[k],
            LUNE_COMM_REQ_ENABLE_NET_IF,
            (const void *)&conf,
            sizeof(conf)))) {
            lune_log(LUNE_INFO, "failed to send request of enabling interface %08x to core %d: %s",
                nrt_ifp->aggr.chan_id_array[j], nrt_ifp->aggr.core_id_array[k], ERR_GET_ERR_STR(err2));
            continue;
        }

        while (-LUNE_ERR_BUF_EMPTY == (err2 = comm_recv_resp_from_core(nrt_ifp->aggr.core_id_array[k],
            &resp_type, &rt_err, NULL, 0))) {
            usleep(sleep_usecs);
        }

        if (0 != rt_err) {
            err2 = rt_err;
            ERR_SET_ERR(-err2);
        }

        if (0 != err2) {
            lune_log(LUNE_INFO, "failed to enable interface %08x on core %d: %s",
                nrt_ifp->aggr.chan_id_array[j], nrt_ifp->aggr.core_id_array[k], ERR_GET_ERR_STR(err2));
            continue;
        }

        lune_assert(LUNE_COMM_RESP_ENABLE_NET_IF == resp_type);
    }

ERR_1:
    return err;
}

static unsigned int net_if_nrt_add_net_if(lune_net_if_type_en type,
    const char *name, const void *conf_val, unsigned int conf_len)
{
    const lune_net_if_nrt_conf_t *conf;
    int core_num;
    cpu_bit_mask_t bit_mask;
    cpu_core_info_t info;
    cpu_bit_mask_t na_bit_mask, np_bit_mask;

    if (unlikely(conf_len != sizeof(lune_net_if_nrt_conf_t))) {
        ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        return LUNE_INVALID_ID;
    }

    conf = (const lune_net_if_nrt_conf_t *)conf_val;
    if (unlikely(NULL == conf->cpu_list)) {
        ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        return LUNE_INVALID_ID;
    }

    if (0 >= (core_num = cpu_parse_cpu_list(conf->cpu_list, &bit_mask))) {
        if (core_num < 0) {
            ERR_SET_ERR(core_num);
        } else {
            ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        return LUNE_INVALID_ID;
    }

    if (LUNE_NET_IF_DPDK == type) {
        conf_val = &conf->dpdk_conf;
        conf_len = sizeof(lune_net_if_dpdk_conf_t);
    } else if (LUNE_NET_IF_DPDK_QUEUE == type) {
        conf_val = &conf->dpdk_queue_conf;
        conf_len = sizeof(lune_net_if_dpdk_queue_conf_t);
    } else {
        conf_val = NULL;
        conf_len = 0;
    }

    lune_assert(!cpu_get_core_info(bit_mask, &info));
    if (info.nrt_num > 0 || info.rt_cp_num > 0) {
        ERR_SET_ERR(LUNE_ERR_CORE_TYPE_ERR);
        return LUNE_INVALID_ID;
    }

    lune_assert((info.rt_na_num + info.rt_np_num) == (unsigned int)core_num);

    if (1 == core_num) {
        int core_id;

        if (info.rt_np_num != 1
            && info.rt_na_num != 1) {
            ERR_SET_ERR(LUNE_ERR_CORE_TYPE_ERR);
            return LUNE_INVALID_ID;
        }

        /* single NA or single NP */
        if (1 == info.rt_np_num) {
            lune_assert(0 <= (core_id = cpu_get_first_core(bit_mask, CPU_CORE_RT_NP)));
        } else {
            lune_assert(0 <= (core_id = cpu_get_first_core(bit_mask, CPU_CORE_RT_NA)));
        }

        return net_if_nrt_add_non_aggr_net_if(type,
            name, conf_val, conf_len, (unsigned int)core_id, (1 == info.rt_np_num) ? 0 : 1);
    }

    if (0 == info.rt_na_num) {
        if (LUNE_NET_IF_DPDK_QUEUE != type) {
            ERR_SET_ERR(LUNE_ERR_NET_IF_TYPE_ERR);
            return LUNE_INVALID_ID;
        }

        /* zero NA and multiple NP */
        return net_if_nrt_add_dpdk_queue_net_if(name,
            &conf->dpdk_queue_conf,
            (unsigned int)core_num,
            bit_mask);
    }

    if (1 == info.rt_na_num) {
        /* single NA and single/multiple NP */
        if (LUNE_NET_IF_DPDK_QUEUE == type
            || (LUNE_NET_IF_CHAN != conf->aggr_conf.chan_type
            && LUNE_NET_IF_DPDK_CHAN != conf->aggr_conf.chan_type)
            || (LUNE_NET_IF_DPDK_CHAN == conf->aggr_conf.chan_type
            && LUNE_NET_IF_DPDK != type)) {
            ERR_SET_ERR(LUNE_ERR_NET_IF_TYPE_ERR);
            return LUNE_INVALID_ID;
        }

        return net_if_nrt_add_aggr_net_if(type,
            name,
            conf_val,
            conf_len,
            &conf->aggr_conf,
            (unsigned int)core_num - info.rt_na_num,
            bit_mask);
    }

    if (0 != (info.rt_np_num % info.rt_na_num)) {
        ERR_SET_ERR(LUNE_ERR_CORE_TYPE_ERR);
        return LUNE_INVALID_ID;
    }

    na_bit_mask = np_bit_mask = bit_mask;
    lune_assert(!cpu_get_core_bit_mask(&na_bit_mask, CPU_CORE_RT_NA));
    lune_assert(!cpu_get_core_bit_mask(&np_bit_mask, CPU_CORE_RT_NP));

    if (LUNE_NET_IF_DPDK_QUEUE != type
        || (LUNE_NET_IF_CHAN != conf->aggr_conf.chan_type
        && LUNE_NET_IF_DPDK_QUEUE_CHAN != conf->aggr_conf.chan_type)) {
        ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        return LUNE_INVALID_ID;
    }

    /* multiple NA and multiple NP */
    return net_if_nrt_add_aggr_dpdk_queue_net_if(name,
        &conf->dpdk_queue_conf,
        &conf->aggr_conf,
        info.rt_na_num,
        info.rt_np_num,
        na_bit_mask,
        np_bit_mask);
}

static int net_if_nrt_del_net_if(unsigned int id)
{
    if (NET_IF_IS_NRT_ID_AGGR(id)) {
        return net_if_nrt_del_aggr_net_if(id);
    } else {
        return net_if_nrt_del_non_aggr_net_if(id);
    }
}

static int net_if_nrt_enable_net_if(unsigned int id)
{
    if (NET_IF_IS_NRT_ID_AGGR(id)) {
        return net_if_nrt_enable_aggr_net_if(id);
    } else {
        return net_if_nrt_enable_non_aggr_net_if(id);
    }
}

static int net_if_nrt_disable_net_if(unsigned int id)
{
    if (NET_IF_IS_NRT_ID_AGGR(id)) {
        return net_if_nrt_disable_aggr_net_if(id);
    } else {
        return net_if_nrt_disable_non_aggr_net_if(id);
    }
}

static int net_if_nrt_get_net_if_opt(unsigned int id,
    lune_net_if_opt_en opt, void *opt_val, unsigned int opt_len)
{
    unsigned int sleep_usecs = NET_IF_NRT_WAIT_RESP_SLEEP_USEC;
    lune_comm_resp_type_en resp_type;
    unsigned int core_id;
    int err, rt_err = 0;
    net_if_nrt_net_if_t *nrt_ifp;
    net_if_comm_get_net_if_opt_conf_t conf;

#ifdef LUNE_DEBUG
    lune_assert(!CORE_IS_RT_CORE());
#endif

    if (unlikely(NULL == (nrt_ifp = s_net_if_nrt_array[NET_IF_GET_NRT_INT_ID(id)]))) {
        return ERR_SET_ERR(LUNE_ERR_ID_NOT_FOUND);
    }

    if (NET_IF_IS_NRT_ID_AGGR(id)) {
        core_id = nrt_ifp->aggr.core_id_array[0];
        conf.id = nrt_ifp->aggr.aggr_id_array[0];
    } else {
        core_id = nrt_ifp->non_aggr.core_id;
        conf.id = nrt_ifp->non_aggr.id;
    }

    conf.opt = opt;
    conf.opt_val = opt_val;
    conf.opt_len = opt_len;
    if (0 != (err = comm_send_req_to_core(core_id,
        LUNE_COMM_REQ_GET_NET_IF_OPT,
        (const void *)&conf,
        sizeof(conf)))) {
        lune_log(LUNE_INFO, "failed to send request of getting option %d of interface %08x"
            " to core %d: %s", opt, id, core_id, ERR_GET_ERR_STR(err));
        return err;
    }

    while (-LUNE_ERR_BUF_EMPTY == (err = comm_recv_resp_from_core(core_id,
        &resp_type, &rt_err, NULL, 0))) {
        usleep(sleep_usecs);
    }

    if (0 != rt_err) {
        err = rt_err;
        ERR_SET_ERR(-err);
    }

    if (0 != err) {
        lune_log(LUNE_INFO, "failed to get option %d of interface %08x on core %d: %s",
            opt, id, core_id, ERR_GET_ERR_STR(err));
        return err;
    }

    lune_assert(LUNE_COMM_RESP_GET_NET_IF_OPT == resp_type);

    return 0;
}

static int net_if_nrt_set_net_if_opt_on_core(unsigned int core_id,
    unsigned int id, lune_net_if_opt_en opt, const void *opt_val, unsigned int opt_len)
{
    int err, rt_err = 0;
    net_if_comm_set_net_if_opt_conf_t conf;
    lune_comm_resp_type_en resp_type;
    unsigned int sleep_usecs = NET_IF_NRT_WAIT_RESP_SLEEP_USEC;

    conf.id = id;
    conf.opt = opt;
    conf.opt_val = opt_val;
    conf.opt_len = opt_len;
    if (0 != (err = comm_send_req_to_core(core_id,
        LUNE_COMM_REQ_SET_NET_IF_OPT,
        (const void *)&conf,
        sizeof(conf)))) {
        lune_log(LUNE_INFO, "failed to send request of setting option %d of interface %08x"
            " to core %d: %s", opt, id, core_id, ERR_GET_ERR_STR(err));
        return err;
    }

    while (-LUNE_ERR_BUF_EMPTY == (err = comm_recv_resp_from_core(core_id,
        &resp_type, &rt_err, NULL, 0))) {
        usleep(sleep_usecs);
    }

    if (0 != rt_err) {
        err = rt_err;
        ERR_SET_ERR(-err);
    }

    if (0 != err) {
        lune_log(LUNE_INFO, "failed to set option %d of interface %08x on core %d: %s",
            opt, id, core_id, ERR_GET_ERR_STR(err));
        return err;
    }

    lune_assert(LUNE_COMM_RESP_SET_NET_IF_OPT == resp_type);

    return 0;
}

static int net_if_nrt_set_net_if_opt(unsigned int id,
    lune_net_if_opt_en opt, const void *opt_val, unsigned int opt_len)
{
    unsigned int i, j;
    int err, last_err = 0;
    net_if_nrt_net_if_t *nrt_ifp;

#ifdef LUNE_DEBUG
    lune_assert(!CORE_IS_RT_CORE());
#endif

    if (unlikely(NULL == (nrt_ifp = s_net_if_nrt_array[NET_IF_GET_NRT_INT_ID(id)]))) {
        return ERR_SET_ERR(LUNE_ERR_ID_NOT_FOUND);
    }

    if (!NET_IF_IS_NRT_ID_AGGR(id)) {
        return net_if_nrt_set_net_if_opt_on_core(nrt_ifp->non_aggr.core_id,
            nrt_ifp->non_aggr.id, opt, opt_val, opt_len);
    }

    if (nrt_ifp->aggr.aggr_num > 0) {
        if (LUNE_NET_IF_OPT_PCAP_START == opt
            || LUNE_NET_IF_OPT_PCAP_STOP == opt
            || LUNE_NET_IF_OPT_DPDK_QUEUE_SET_DISTRIB == opt
            || LUNE_NET_IF_OPT_DPDK_QUEUE_CLEAR_DISTRIB == opt) {
            j = 1;
        } else {
            j = nrt_ifp->aggr.aggr_num;
        }

        for (i = 0; i < j; i++) {
            if (0 != (err = net_if_nrt_set_net_if_opt_on_core(nrt_ifp->aggr.core_id_array[i],
                nrt_ifp->aggr.aggr_id_array[i], opt, opt_val, opt_len))) {
                last_err = err;
                continue;
            }
        }
    } else {
        if (LUNE_NET_IF_OPT_PCAP_START == opt
            || LUNE_NET_IF_OPT_PCAP_STOP == opt
            || LUNE_NET_IF_OPT_DPDK_QUEUE_SET_DISTRIB == opt
            || LUNE_NET_IF_OPT_DPDK_QUEUE_CLEAR_DISTRIB == opt) {
            j = 1;
        } else {
            j = nrt_ifp->aggr.chan_num;
        }

        for (i = 0; i < j; i++) {
            if (0 != (err = net_if_nrt_set_net_if_opt_on_core(
                nrt_ifp->aggr.core_id_array[nrt_ifp->aggr.core_num - nrt_ifp->aggr.chan_num + i],
                nrt_ifp->aggr.chan_id_array[i], opt, opt_val, opt_len))) {
                last_err = err;
                continue;
            }
        }
    }

    return last_err;
}

unsigned int lune_add_net_if(lune_net_if_type_en type,
    const char *name, const void *conf_val, unsigned int conf_len)
{
    net_if_t *ifp;
    net_if_drv_t *drv;

    if (type < LUNE_NET_IF_STD
        || type >= LUNE_NET_IF_MAX
        || NULL == name
        || (NULL == conf_val && 0 != conf_len)
        || (NULL != conf_val && 0 == conf_len)) {
        ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        return LUNE_INVALID_ID;
    }

#ifndef LUNE_BUILD_DPDK
    if (type >= LUNE_NET_IF_DPDK
        && type <= LUNE_NET_IF_DPDK_QUEUE_CHAN) {
        ERR_SET_ERR(LUNE_ERR_NOT_SUPPORTED);
        return LUNE_INVALID_ID;
    }
#endif

    drv = CORE_IS_RT_CORE() ? &s_net_if_drv_array[type] : &g_net_if_drv_array[type];
    lune_log(LUNE_VBS, "adding %s interface %s", drv->name, name);

    if (!CORE_IS_RT_CORE()) {
        unsigned int id;
        /* non-realtime route */
        id = net_if_nrt_add_net_if(type, name, conf_val, conf_len);
        if (LUNE_INVALID_ID != id) {
            lune_log(LUNE_DBG, "interface %s added (%08x)", name, id);
        }
        return id;
    }

    SCHED_CHECK_POINT();

    if (strlen(name) > LUNE_MAX_SHORT_NAME_LEN) {
        ERR_SET_ERR(LUNE_ERR_NAME_TOO_LONG);
        return LUNE_INVALID_ID;
    }

    if (unlikely(NULL == drv->add_net_if)) {
        /* e.g., add dpdk interface without enable_dpdk */
        ERR_SET_ERR(LUNE_ERR_NET_IF_TYPE_NOT_SUPPORTED);
        return LUNE_INVALID_ID;
    }

    if (NULL == (ifp = net_if_add_net_if(type, drv, name, conf_val, conf_len))) {
        return LUNE_INVALID_ID;
    }

    lune_log(LUNE_DBG, "interface %s added (%08x)", name, ifp->id);
    return ifp->id;
}

int lune_del_net_if(unsigned int id)
{
    net_if_t *ifp;
    int err;

    if (LUNE_INVALID_ID == id) {
        return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
    }

    lune_log(LUNE_VBS, "deleting interface %08x", id);

    if (!CORE_IS_RT_CORE()) {
        /* non-realtime route */
        if (unlikely(!NET_IF_IS_NRT_ID(id))) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        if (0 == (err = net_if_nrt_del_net_if(id))) {
            lune_log(LUNE_DBG, "interface %08x deleted", id);
        }

        return err;
    }

    SCHED_CHECK_POINT();

    if (NULL == (ifp = net_if_get_net_if_by_id(id))) {
        return ERR_SET_ERR(LUNE_ERR_ID_NOT_FOUND);
    }

    if (0 == (err = net_if_del_net_if(ifp))) {
        lune_log(LUNE_DBG, "interface %08x deleted", id);
    }

    return err;
}

unsigned int lune_get_net_if(lune_net_if_type_en type, const char *name)
{
    net_if_t *ifp;

    if (type < LUNE_NET_IF_STD || type >= LUNE_NET_IF_MAX || NULL == name) {
        ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        return LUNE_INVALID_ID;
    }

    if (unlikely(!CORE_IS_RT_CORE())) {
        return ERR_SET_ERR(LUNE_ERR_NOT_SUPPORTED);
    }

    SCHED_CHECK_POINT();

    if (NULL == (ifp = net_if_get_net_if_by_name(type, name))) {
        ERR_SET_ERR(LUNE_ERR_ID_NOT_FOUND);
        return LUNE_INVALID_ID;
    }

    return ifp->id;
}

int lune_enable_net_if(unsigned int id)
{
    net_if_t *ifp;
    int err;

    if (LUNE_INVALID_ID == id) {
        return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
    }

    lune_log(LUNE_VBS, "enabling interface %08x", id);

    if (!CORE_IS_RT_CORE()) {
        /* non-realtime route */
        if (unlikely(!NET_IF_IS_NRT_ID(id))) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        if (0 == (err = net_if_nrt_enable_net_if(id))) {
            lune_log(LUNE_DBG, "interface %08x enabled", id);
        }

        return err;
    }

    SCHED_CHECK_POINT();

    if (NULL == (ifp = net_if_get_net_if_by_id(id))) {
        return ERR_SET_ERR(LUNE_ERR_ID_NOT_FOUND);
    }

    if (NET_IF_IS_ACTIVE(ifp)) {
        return ERR_SET_ERR(LUNE_ERR_NET_IF_ACTIVE);
    }

    if (0 == (err = net_if_enable_net_if(ifp))) {
        lune_log(LUNE_DBG, "interface %08x enabled", id);
    }

    return err;
}

int lune_disable_net_if(unsigned int id)
{
    net_if_t *ifp;
    int err;

    if (LUNE_INVALID_ID == id) {
        return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
    }

    lune_log(LUNE_VBS, "disabling interface %08x", id);

    if (!CORE_IS_RT_CORE()) {
        /* non-realtime route */
        if (unlikely(!NET_IF_IS_NRT_ID(id))) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        if (0 == (err = net_if_nrt_disable_net_if(id))) {
            lune_log(LUNE_DBG, "interface %08x disabled", id);
        }

        return err;
    }

    SCHED_CHECK_POINT();

    if (NULL == (ifp = net_if_get_net_if_by_id(id))) {
        return ERR_SET_ERR(LUNE_ERR_ID_NOT_FOUND);
    }

    if (!NET_IF_IS_ACTIVE(ifp)) {
        return ERR_SET_ERR(LUNE_ERR_NET_IF_INACTIVE);
    }

    if (0 == (err = net_if_disable_net_if(ifp))) {
        lune_log(LUNE_DBG, "interface %08x disabled", id);
    }

    return err;
}

static int net_if_set_net_if_aggr(net_if_t *ifp, const lune_net_if_aggr_conf_t *conf)
{
    if (NET_IF_IS_ACTIVE(ifp)) {
        return ERR_SET_ERR(LUNE_ERR_NET_IF_ACTIVE);
    }

    if (NET_IF_IS_AGGR(ifp)) {
        return ERR_SET_ERR(LUNE_ERR_ALREADY_SET);
    }

    if (NET_IF_IS_SOCKET(ifp)) {
        return ERR_SET_ERR(LUNE_ERR_NOT_SUPPORTED);
    }

    if (LUNE_NET_IF_AGGR_CUSTOM == conf->type
        && LUNE_NET_IF_DPDK_QUEUE == ifp->type) {
        return ERR_SET_ERR(LUNE_ERR_NOT_SUPPORTED);
    }

    if (NULL == (ifp->aip = aggr_add_net_if(ifp->name, conf, ifp))) {
        return ERR_GET_LAST_ERR();
    }

    NET_IF_SET_AGGR(ifp);

    return 0;
}

static int net_if_clear_net_if_aggr(net_if_t *ifp)
{
    int err;

    if (NET_IF_IS_ACTIVE(ifp)) {
        return ERR_SET_ERR(LUNE_ERR_NET_IF_ACTIVE);
    }

    if (!NET_IF_IS_AGGR(ifp)) {
        return ERR_SET_ERR(LUNE_ERR_NOT_SET);
    }

    if (0 != (err = aggr_del_net_if(ifp->aip))) {
        return err;
    }

    ifp->aip = NULL;
    NET_IF_SET_NONAGGR(ifp);

    return 0;
}

int lune_get_net_if_opt(unsigned int id,
    lune_net_if_opt_en opt, void *opt_val, unsigned int opt_len)
{
    net_if_t *ifp;
    int err;

    if (LUNE_INVALID_ID == id || NULL == opt_val) {
        return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
    }

    if (!CORE_IS_RT_CORE()) {
        /* non-realtime route */
        if (unlikely(!NET_IF_IS_NRT_ID(id))) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        return net_if_nrt_get_net_if_opt(id, opt, opt_val, opt_len);
    }

    SCHED_CHECK_POINT();

    if (NULL == (ifp = net_if_get_net_if_by_id(id))) {
        return ERR_SET_ERR(LUNE_ERR_ID_NOT_FOUND);
    }

    switch (opt) {
    case LUNE_NET_IF_OPT_GET_MTU:
        if (sizeof(unsigned short) != opt_len) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }
        *(unsigned short *)opt_val = ifp->mtu;
        break;
    case LUNE_NET_IF_OPT_GET_STATS:
        if (sizeof(lune_net_if_stats_t) != opt_len) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        if (0 != (err = ifp->drv->get_opt(ifp->net_if_data,
            NET_IF_OPT_GET_STATS, (unsigned char *)opt_val, sizeof(lune_net_if_stats_t)))) {
            lune_log(LUNE_WARN, "failed to get statistics on %s: %s",
                ifp->name, ERR_GET_LAST_ERR_STR());
            return err;
        }

        ((lune_net_if_stats_t *)opt_val)->byte_in_rate = ifp->stats.byte_in_rate;
        ((lune_net_if_stats_t *)opt_val)->byte_out_rate = ifp->stats.byte_out_rate;
        ((lune_net_if_stats_t *)opt_val)->pkt_in_rate = ifp->stats.pkt_in_rate;
        ((lune_net_if_stats_t *)opt_val)->pkt_out_rate = ifp->stats.pkt_out_rate;
        break;
    case LUNE_NET_IF_OPT_GET_TCP_STATS:
        if (sizeof(lune_net_if_tcp_stats_t) != opt_len) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }
        memcpy(opt_val, &ifp->tcp_stats, sizeof(lune_net_if_tcp_stats_t));
        break;
    case LUNE_NET_IF_OPT_GET_SSL_STATS:
        if (sizeof(lune_net_if_ssl_stats_t) != opt_len) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }
        memcpy(opt_val, &ifp->ssl_stats, sizeof(lune_net_if_ssl_stats_t));
        break;
    case LUNE_NET_IF_OPT_GET_CHAN_ID:
        return ifp->drv->get_opt(ifp->net_if_data,
            NET_IF_OPT_GET_CHAN_ID, (unsigned char *)opt_val, sizeof(opt_len));
    default:
        return ifp->drv->get_opt(ifp->net_if_data,
            opt, (unsigned char *)opt_val, sizeof(opt_len));
    }

    return 0;
}

int lune_set_net_if_opt(unsigned int id,
    lune_net_if_opt_en opt, const void *opt_val, unsigned int opt_len)
{
    net_if_t *ifp;
    int err;

    if (LUNE_INVALID_ID == id || opt >= LUNE_NET_IF_OPT_MAX) {
        return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
    }

    if (!CORE_IS_RT_CORE()) {
        /* non-realtime route */
        if (unlikely(!NET_IF_IS_NRT_ID(id))) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        return net_if_nrt_set_net_if_opt(id, opt, opt_val, opt_len);
    }

    SCHED_CHECK_POINT();

    if (NULL == (ifp = net_if_get_net_if_by_id(id))) {
        return ERR_SET_ERR(LUNE_ERR_ID_NOT_FOUND);
    }

    switch (opt) {
    case LUNE_NET_IF_OPT_CLEAR_ALL_STATS:
        net_if_clear_net_if_stats(ifp);
        break;
    case LUNE_NET_IF_OPT_SET_MTU:
    {
        unsigned short mtu;

        if (NULL == opt_val || sizeof(unsigned short) != opt_len) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        mtu = *(const unsigned short *)opt_val;
        if (LUNE_NET_IF_MIN_MTU > mtu
            || LUNE_NET_IF_MAX_MTU < mtu) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_MTU);
        }

        if (NET_IF_IS_AGGR(ifp)) {
            /* mtu MUST be set before LUNE_NET_IF_OPT_SET_AGGR is set */
            return ERR_SET_ERR(LUNE_ERR_NOT_SUPPORTED);
        }

        if (0 != (err = ifp->drv->set_opt(ifp->net_if_data,
            NET_IF_OPT_SET_MTU, (const unsigned char *)&mtu, sizeof(mtu)))) {
            lune_log(LUNE_WARN, "failed to set mtu on %s: %s", ifp->name, ERR_GET_ERR_STR(err));
            return err;
        }

        ifp->mtu = mtu;

        break;
    }
    case LUNE_NET_IF_OPT_PCAP_START:
    {
        char buf[LUNE_MAX_NAME_BUF_LEN];
        const char *file_name;

        if ((NULL == opt_val && 0 != opt_len)
            || (NULL != opt_val && sizeof(lune_net_if_pcap_t) != opt_len)) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        if (NULL == opt_val) {
            sprintf(buf, "%s.pcap", ifp->name);
            lune_str_replace_char(buf, ':', '_');
            lune_str_replace_char(buf, '/', '_');
            file_name = buf;
        } else {
            if (NULL == (file_name = ((const lune_net_if_pcap_t *)opt_val)->file_name)) {
                return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
            }
        }

#ifdef LUNE_BUILD_DPDK
        if (LUNE_NET_IF_DPDK_QUEUE == ifp->type
            || LUNE_NET_IF_DPDK == ifp->type) {
            return ifp->drv->set_opt(ifp->net_if_data,
                NET_IF_OPT_PCAP_START, opt_val, opt_len);
        }
#endif

        if (NET_IF_IS_CAP_ENABLED(ifp)) {
            return ERR_SET_ERR(LUNE_ERR_ALREADY_STARTED);
        }

        if (NULL == (ifp->cap_fp = cap_start(file_name))) {
            return ERR_GET_LAST_ERR();
        }

        break;
    }
    case LUNE_NET_IF_OPT_PCAP_STOP:
        if (NULL != opt_val || 0 != opt_len) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

#ifdef LUNE_BUILD_DPDK
        if (LUNE_NET_IF_DPDK_QUEUE == ifp->type
            || LUNE_NET_IF_DPDK == ifp->type) {
            return ifp->drv->set_opt(ifp->net_if_data,
                NET_IF_OPT_PCAP_STOP, NULL, 0);
        }
#endif

        if (!NET_IF_IS_CAP_ENABLED(ifp)) {
            lune_assert(NULL == ifp->cap_fp);
            return ERR_SET_ERR(LUNE_ERR_NOT_STARTED);
        }

        cap_stop(ifp->cap_fp);
        ifp->cap_fp = NULL;

        break;
    case LUNE_NET_IF_OPT_DPDK_QUEUE_PCAP_START:
    {
        char buf[LUNE_MAX_NAME_BUF_LEN];
        const char *file_name;

        if ((NULL == opt_val && 0 != opt_len)
            || (NULL != opt_val && sizeof(lune_net_if_pcap_t) != opt_len)) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        if (LUNE_NET_IF_DPDK_QUEUE != ifp->type) {
            return ERR_SET_ERR(LUNE_ERR_NET_IF_TYPE_ERR);
        }

        if (NULL == opt_val) {
            sprintf(buf, "%s.pcap", ifp->name);
            lune_str_replace_char(buf, ':', '_');
            lune_str_replace_char(buf, '/', '_');
            file_name = buf;
        } else {
            if (NULL == (file_name = ((const lune_net_if_pcap_t *)opt_val)->file_name)) {
                return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
            }
        }

        if (NET_IF_IS_CAP_ENABLED(ifp)) {
            return ERR_SET_ERR(LUNE_ERR_ALREADY_STARTED);
        }

        if (NULL == (ifp->cap_fp = cap_start(file_name))) {
            return ERR_GET_LAST_ERR();
        }

        break;
    }
    case LUNE_NET_IF_OPT_DPDK_QUEUE_PCAP_STOP:
        if (NULL != opt_val || 0 != opt_len) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        if (LUNE_NET_IF_DPDK_QUEUE != ifp->type) {
            return ERR_SET_ERR(LUNE_ERR_NET_IF_TYPE_ERR);
        }

        if (!NET_IF_IS_CAP_ENABLED(ifp)) {
            lune_assert(NULL == ifp->cap_fp);
            return ERR_SET_ERR(LUNE_ERR_NOT_STARTED);
        }

        cap_stop(ifp->cap_fp);
        ifp->cap_fp = NULL;

        break;
    case LUNE_NET_IF_OPT_SET_AGGR:
        if (NULL == opt_val || sizeof(lune_net_if_aggr_conf_t) != opt_len) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        if (unlikely(NULL == ifp->drv->recv_fwd_pkt
            || NULL == ifp->drv->recv_free_pkt)) {
            /* not supported, e.g. LUNE_NET_IF_CHAN */
            return ERR_SET_ERR(LUNE_ERR_NOT_SUPPORTED);
        }

        if (!CORE_IS_NA()) {
            lune_log(LUNE_INFO, "set aggregated interface %s on NP", ifp->name);
            /* keep going */
        }

        return net_if_set_net_if_aggr(ifp, (const lune_net_if_aggr_conf_t *)opt_val);
    case LUNE_NET_IF_OPT_CLEAR_AGGR:
        if (NULL != opt_val || 0 != opt_len) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        if (unlikely(NULL == ifp->drv->recv_fwd_pkt
            || NULL == ifp->drv->recv_free_pkt)) {
            /* not supported, e.g. LUNE_NET_IF_CHAN */
            return ERR_SET_ERR(LUNE_ERR_NOT_SUPPORTED);
        }

        return net_if_clear_net_if_aggr(ifp);
    case LUNE_NET_IF_OPT_SET_HOOK:
        if (NULL == opt_val || sizeof(lune_net_if_hook_t) != opt_len) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        if (NET_IF_IS_SOCKET(ifp)) {
            return ERR_SET_ERR(LUNE_ERR_NOT_SUPPORTED);
        }

        if (NULL == ((const lune_net_if_hook_t *)opt_val)->send
            && NULL == ((const lune_net_if_hook_t *)opt_val)->recv) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        if (NET_IF_IS_HOOK(ifp)) {
            return ERR_SET_ERR(LUNE_ERR_ALREADY_SET);
        }

        NET_IF_SET_HOOK(ifp);
        memcpy(&ifp->hook, opt_val, sizeof(lune_net_if_hook_t));
        break;
    case LUNE_NET_IF_OPT_CLEAR_HOOK:
        if (NULL != opt_val || 0 != opt_len) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        if (!NET_IF_IS_HOOK(ifp)) {
            return ERR_SET_ERR(LUNE_ERR_NOT_SET);
        }

        lune_assert(!NET_IF_IS_SOCKET(ifp));

        memset(&ifp->hook, 0x00, sizeof(ifp->hook));
        NET_IF_CLEAR_HOOK(ifp);
        break;
    case LUNE_NET_IF_OPT_DPDK_QUEUE_SET_DISTRIB:
        if (NULL != opt_val || 0 != opt_len) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        if (LUNE_NET_IF_DPDK_QUEUE != ifp->type) {
            return ERR_SET_ERR(LUNE_ERR_NOT_SUPPORTED);
        }

        return ifp->drv->set_opt(ifp->net_if_data,
            NET_IF_OPT_DPDK_QUEUE_SET_DISTRIB, NULL, 0);
    case LUNE_NET_IF_OPT_DPDK_QUEUE_CLEAR_DISTRIB:
        if (NULL != opt_val || 0 != opt_len) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        if (LUNE_NET_IF_DPDK_QUEUE != ifp->type) {
            return ERR_SET_ERR(LUNE_ERR_NOT_SUPPORTED);
        }

        return ifp->drv->set_opt(ifp->net_if_data,
            NET_IF_OPT_DPDK_QUEUE_CLEAR_DISTRIB, NULL, 0);
    default:
        return ERR_SET_ERR(LUNE_ERR_OPT_NOT_FOUND);
    }

    return 0;
}

static inline int net_if_is_valid_pkt_size(const unsigned char *buf, unsigned int len, net_if_t *ifp)
{
    const lune_eth_hdr_t *ethh;
    const lune_vlan_field_t *vf;

    ethh = (const lune_eth_hdr_t *)buf;
    if (ethh->type != ETH_TYPE_VLAN_N) {
        return (len <= NET_IF_GET_MAX_ETH_PKT_SIZE(ifp));
    }

    vf = (const lune_vlan_field_t *)&ethh->type + 1;
    if (vf->type != ETH_TYPE_VLAN_N) {
        return (len <= NET_IF_GET_MAX_VLAN_PKT_SIZE(ifp));
    }

    return (len <= NET_IF_GET_MAX_QINQ_PKT_SIZE(ifp));
}

int lune_net_if_send(unsigned int id, const unsigned char *buf, unsigned int len)
{
    net_if_t *ifp;
    int err;

    if (unlikely(LUNE_INVALID_ID == id)) {
        return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
    }

    if (unlikely(!CORE_IS_RT_CORE())) {
        return ERR_SET_ERR(LUNE_ERR_NOT_SUPPORTED);
    }

    SCHED_CHECK_POINT();

    if (NULL == (ifp = net_if_get_net_if_by_id(id))) {
        return ERR_SET_ERR(LUNE_ERR_ID_NOT_FOUND);
    }

    if (unlikely(!NET_IF_IS_ACTIVE(ifp))) {
        return ERR_SET_ERR(LUNE_ERR_NET_IF_INACTIVE);
    }

    if (ifp->max_tx_data_rate_per_ms != NET_IF_MAX_TX_DATA_RATE_UNLIMITED
        && ifp->tx_rt_data_per_ms >= ifp->max_tx_data_rate_per_ms) {
        return ERR_SET_ERR(LUNE_ERR_EXCEED_LIMITS);
    }

    if (unlikely(!net_if_is_valid_pkt_size(buf, len, ifp))) {
        return ERR_SET_ERR(LUNE_ERR_OVERSIZED_PKT);
    }

    if (likely(NULL == ifp->hook.send)
        || LUNE_NET_IF_HOOK_PKT_NONE == ifp->hook.send(ifp->hook.data, buf, len)) {
        if (0 != (err = ifp->drv->send(ifp->net_if_data, buf, len))) {
            return err;
        }

        ifp->tx_rt_data_per_ms += len;

        /* capture sent packets if enabled */
        NET_IF_CAP_PKT(ifp, buf, len);
    }

    return 0;
}

static int net_if_nrt_connect_net_if(unsigned int id1, unsigned id2)
{
    unsigned int core1_id;
    unsigned int core2_id;
    unsigned int if1_id;
    unsigned int if2_id;
    int err, rt_err = 0;
    lune_comm_resp_type_en resp_type;
    unsigned int sleep_usecs = NET_IF_NRT_WAIT_RESP_SLEEP_USEC;
    net_if_comm_connect_net_if_conf_t conf;
    net_if_nrt_net_if_t *nrt_ifp;

#ifdef LUNE_DEBUG
    lune_assert(!CORE_IS_RT_CORE());
#endif

    if (unlikely(NULL == (nrt_ifp = s_net_if_nrt_array[NET_IF_GET_NRT_INT_ID(id1)]))) {
        return ERR_SET_ERR(LUNE_ERR_ID_NOT_FOUND);
    }

    if (NET_IF_IS_NRT_ID_AGGR(id1)) {
        if (nrt_ifp->aggr.aggr_num != 1) {
            return ERR_SET_ERR(LUNE_ERR_NET_IF_TYPE_ERR);
        }

        core1_id = nrt_ifp->aggr.core_id_array[0];
        if1_id = nrt_ifp->aggr.aggr_id_array[0];
    } else {
        core1_id = nrt_ifp->non_aggr.core_id;
        if1_id = nrt_ifp->non_aggr.id;
    }

    if (unlikely(NULL == (nrt_ifp = s_net_if_nrt_array[NET_IF_GET_NRT_INT_ID(id2)]))) {
        return ERR_SET_ERR(LUNE_ERR_ID_NOT_FOUND);
    }

    if (NET_IF_IS_NRT_ID_AGGR(id2)) {
        if (nrt_ifp->aggr.aggr_num != 1) {
            return ERR_SET_ERR(LUNE_ERR_NET_IF_TYPE_ERR);
        }

        core2_id = nrt_ifp->aggr.core_id_array[0];
        if2_id = nrt_ifp->aggr.aggr_id_array[0];
    } else {
        core2_id = nrt_ifp->non_aggr.core_id;
        if2_id = nrt_ifp->non_aggr.id;
    }

    conf.id = if1_id;
    conf.peer_id = if2_id;
    conf.peer_core_id = core2_id;
    if (0 != (err = comm_send_req_to_core(core1_id,
        LUNE_COMM_REQ_CONNECT_NET_IF,
        (const void *)&conf,
        sizeof(conf)))) {
        lune_log(LUNE_INFO, "failed to send request of connecting interface %08x on core %d "
            "to interface %08x on core %d: %s", id1, core1_id, id2, core2_id, ERR_GET_ERR_STR(err));
        return err;
    }

    while (-LUNE_ERR_BUF_EMPTY == (err = comm_recv_resp_from_core(core1_id,
        &resp_type, &rt_err, NULL, 0))) {
        usleep(sleep_usecs);
    }

    if (0 != rt_err) {
        err = rt_err;
        ERR_SET_ERR(-err);
    }

    if (0 != err) {
        lune_log(LUNE_INFO, "failed to connect interface %08x on core %d to interface %08x "
            "on core %d: %s", id1, core1_id, id2, core2_id, ERR_GET_ERR_STR(err));
        return err;
    }

    lune_assert(LUNE_COMM_RESP_CONNECT_NET_IF == resp_type);

    return 0;
}

static int net_if_nrt_disconnect_net_if(unsigned int id)
{
    unsigned int core_id;
    int err, rt_err = 0;
    lune_comm_resp_type_en resp_type;
    unsigned int sleep_usecs = NET_IF_NRT_WAIT_RESP_SLEEP_USEC;
    net_if_conn_type_en conn_type;
    net_if_comm_disconnect_net_if_conf_t conf;

#ifdef LUNE_DEBUG
    lune_assert(!CORE_IS_RT_CORE());
#endif

    if (0 != (err = net_if_nrt_get_net_if_opt(id, NET_IF_OPT_GET_CONN_TYPE, &conn_type, sizeof(conn_type)))) {
        return err;
    }

    if (NET_IF_CONN_TYPE_NONE == conn_type) {
        return ERR_SET_ERR(LUNE_ERR_NET_IF_NOT_CONNECTED);
    }

    if (NET_IF_CONN_TYPE_REMOTE_PASSIVE == conn_type) {
        net_if_peer_net_if_t peer;
        if (unlikely(0 != (err = net_if_nrt_get_net_if_opt(id, NET_IF_OPT_GET_PEER_NET_IF, &peer, sizeof(peer))))) {
            return err;
        }

        core_id = peer.core_id;
        conf.id = peer.id;
    } else {
        net_if_nrt_net_if_t *nrt_ifp;

        lune_assert(NET_IF_CONN_TYPE_LOCAL == conn_type || NET_IF_CONN_TYPE_REMOTE_ACTIVE == conn_type);

        if (unlikely(NULL == (nrt_ifp = s_net_if_nrt_array[NET_IF_GET_NRT_INT_ID(id)]))) {
            return ERR_SET_ERR(LUNE_ERR_ID_NOT_FOUND);
        }

        if (NET_IF_IS_NRT_ID_AGGR(id)) {
            if (nrt_ifp->aggr.aggr_num != 1) {
                return ERR_SET_ERR(LUNE_ERR_NET_IF_TYPE_ERR);
            }

            core_id = nrt_ifp->aggr.core_id_array[0];
            conf.id = nrt_ifp->aggr.aggr_id_array[0];
        } else {
            core_id = nrt_ifp->non_aggr.core_id;
            conf.id = nrt_ifp->non_aggr.id;
        }
    }

    if (0 != (err = comm_send_req_to_core(core_id,
        LUNE_COMM_REQ_DISCONNECT_NET_IF,
        (const void *)&conf,
        sizeof(conf)))) {
        lune_log(LUNE_INFO, "failed to send request of disconnecting interface %08x on core %d: %s",
            id, core_id, ERR_GET_ERR_STR(err));
        return err;
    }

    while (-LUNE_ERR_BUF_EMPTY == (err = comm_recv_resp_from_core(core_id,
        &resp_type, &rt_err, NULL, 0))) {
        usleep(sleep_usecs);
    }

    if (0 != rt_err) {
        err = rt_err;
        ERR_SET_ERR(-err);
    }

    if (0 != err) {
        lune_log(LUNE_INFO, "failed to disconnect interface %08x on core %d: %s",
            id, core_id, ERR_GET_ERR_STR(err));
        return err;
    }

    lune_assert(LUNE_COMM_RESP_DISCONNECT_NET_IF == resp_type);

    return 0;
}

static int net_if_connect_local_net_if(unsigned int id, unsigned peer_id)
{
    net_if_t *ifp;
    int err;

    if (NULL == (ifp = net_if_get_net_if_by_id(id))) {
        return ERR_SET_ERR(LUNE_ERR_ID_NOT_FOUND);
    }

    if (0 != (err = ifp->drv->set_opt(ifp->net_if_data,
        NET_IF_OPT_CONNECT_LOCAL, (const unsigned char *)&peer_id, sizeof(peer_id)))) {
        lune_log(LUNE_WARN, "failed to connect %08x to %08x: %s", peer_id, id, ERR_GET_ERR_STR(err));
        return err;
    }

    return 0;
}

static int net_if_connect_remote_net_if(unsigned int id, unsigned int peer_id, unsigned int peer_core_id)
{
    net_if_t *ifp;
    int err;
    net_if_peer_net_if_t peer;

    if (NULL == (ifp = net_if_get_net_if_by_id(id))) {
        return ERR_SET_ERR(LUNE_ERR_ID_NOT_FOUND);
    }

    peer.id = peer_id;
    peer.core_id = peer_core_id;
    if (0 != (err = ifp->drv->set_opt(ifp->net_if_data,
        NET_IF_OPT_CONNECT_REMOTE, (const unsigned char *)&peer, sizeof(peer)))) {
        lune_log(LUNE_WARN, "failed to connect interface %08x on core %d to interface %08x on core %d: %s",
                id, CORE_GET_ID(), peer_id, peer_core_id, ERR_GET_ERR_STR(err));
        return err;
    }

    return 0;
}

static int net_if_disconnect_net_if(unsigned int id)
{
    net_if_t *ifp;
    int err;
    unsigned int conn_type;

    if (NULL == (ifp = net_if_get_net_if_by_id(id))) {
        return ERR_SET_ERR(LUNE_ERR_ID_NOT_FOUND);
    }

    if (0 != (err = ifp->drv->get_opt(ifp->net_if_data,
        NET_IF_OPT_GET_CONN_TYPE, (unsigned char *)&conn_type, sizeof(conn_type)))) {
        lune_log(LUNE_INFO, "failed to get option %d on %s: %s",
            NET_IF_OPT_GET_CONN_TYPE, ifp->name, ERR_GET_ERR_STR(err));
        return err;
    }

    switch (conn_type) {
    case NET_IF_CONN_TYPE_NONE:
        return ERR_SET_ERR(LUNE_ERR_NET_IF_NOT_CONNECTED);
    case NET_IF_CONN_TYPE_LOCAL:
        if (0 != (err = ifp->drv->set_opt(ifp->net_if_data,
            NET_IF_OPT_DISCONNECT_LOCAL, NULL, 0))) {
            lune_log(LUNE_WARN, "failed to disconnect %s: %s", ifp->name, ERR_GET_ERR_STR(err));
            return err;
        }
        break;
    case NET_IF_CONN_TYPE_REMOTE_ACTIVE:
        if (0 != (err = ifp->drv->set_opt(ifp->net_if_data,
            NET_IF_OPT_DISCONNECT_REMOTE, NULL, 0))) {
            lune_log(LUNE_WARN, "failed to disconnect %s: %s", ifp->name, ERR_GET_ERR_STR(err));
            return err;
        }
        break;
    case NET_IF_CONN_TYPE_REMOTE_PASSIVE:
        return ERR_SET_ERR(LUNE_ERR_NOT_SUPPORTED);
    default:
        lune_assert(0);
        return ERR_SET_ERR(LUNE_ERR_NET_IF_INTERNAL);
    }

    return 0;
}

int lune_connect_net_if(unsigned int id1, unsigned id2)
{
    if (unlikely(LUNE_INVALID_ID == id1 || LUNE_INVALID_ID == id2)) {
        return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
    }

    if (!CORE_IS_RT_CORE()) {
        /* non-realtime route */
        if (unlikely(!NET_IF_IS_NRT_ID(id1)
            || !NET_IF_IS_NRT_ID(id2))) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        return net_if_nrt_connect_net_if(id1, id2);
    }

    SCHED_CHECK_POINT();

    return net_if_connect_local_net_if(id1, id2);
}

int lune_disconnect_net_if(unsigned int id)
{
    if (unlikely(LUNE_INVALID_ID == id)) {
        return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
    }

    if (!CORE_IS_RT_CORE()) {
        /* non-realtime route */
        if (unlikely(!NET_IF_IS_NRT_ID(id))) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        return net_if_nrt_disconnect_net_if(id);
    }

    SCHED_CHECK_POINT();

    return net_if_disconnect_net_if(id);
}

int net_if_send_pkt(void *p, pbuf_t *pbuf)
{
    net_if_t *ifp = (net_if_t *)p;
    int err;
    unsigned int len;

    if (unlikely(!NET_IF_IS_ACTIVE(ifp))) {
        return ERR_SET_ERR(LUNE_ERR_NET_IF_INACTIVE);
    }

    if (ifp->max_tx_data_rate_per_ms != NET_IF_MAX_TX_DATA_RATE_UNLIMITED
        && ifp->tx_rt_data_per_ms >= ifp->max_tx_data_rate_per_ms) {
        return ERR_SET_ERR(LUNE_ERR_EXCEED_LIMITS);
    }

    len = PBUF_GET_PKT_LEN(pbuf);

    if (likely(NULL == ifp->hook.send)
        || (LUNE_NET_IF_HOOK_PKT_NONE == ifp->hook.send(ifp->hook.data, PBUF_GET_HDR(pbuf), len))) {
        NET_IF_SET_CURR_TX_PBUF(pbuf);
        if (0 != (err = ifp->drv->send(ifp->net_if_data, PBUF_GET_HDR(pbuf), len))) {
            NET_IF_SET_CURR_TX_PBUF(NULL);
            return ERR_SET_ERR(LUNE_ERR_NET_IF_SEND_FAILED);
        }

        switch (PBUF_GET_L4_TYPE(pbuf)) {
        case PBUF_L4_TYPE_TCP:
            NET_IF_TCP_INC_PKT_OUT(ifp);
            NET_IF_TCP_ADD_DATA_OUT(ifp, pbuf->tcp.data_len);
            break;
        default:
            break;
        }

        ifp->tx_rt_data_per_ms += len;

        /* capture sent packets if enabled */
        NET_IF_CAP_PKT(ifp, PBUF_GET_HDR(pbuf), len);

        NET_IF_SET_CURR_TX_PBUF(NULL);
    }

    return 0;
}

int net_if_init(void)
{
    int i;

    s_net_if_nrt_cnt = 0;
    s_net_if_nrt_array_offset = 0;
    for (i = 0; i < LUNE_NET_IF_MAX_NUM; i++) {
        s_net_if_nrt_array[i] = NULL;
    }

    return 0;
}

void net_if_fini(void)
{
    int i;

    s_net_if_nrt_array_offset = 0;

    if (unlikely(0 != s_net_if_nrt_cnt)) {
        lune_log(LUNE_WARN, "%d interfaces not deleted while releasing interface resource", s_net_if_nrt_cnt);
        for (i = 0; i < LUNE_NET_IF_MAX_NUM; i++) {
            if (NULL != s_net_if_nrt_array[i]) {
                /* disable it no matter whether it's active or not */
                (void)net_if_nrt_disable_net_if(s_net_if_nrt_array[i]->nrt_id);
                (void)net_if_nrt_del_net_if(s_net_if_nrt_array[i]->nrt_id);
                s_net_if_nrt_array[i] = NULL;
            }
        }
    }
}

int net_if_local_init(void)
{
    int i;

    s_net_if_rt_cnt = 0;
    s_net_if_rt_array_offset = 0;
    for (i = 0; i < LUNE_NET_IF_MAX_NUM; i++) {
        s_net_if_rt_array[i] = NULL;
    }
    NET_IF_CLEAR_CURR_NET_IF();

    memcpy(s_net_if_drv_array, g_net_if_drv_array, sizeof(net_if_drv_t) * LUNE_NET_IF_MAX);

    g_net_if_curr_tx_pbuf = NULL;

    return 0;
}

void net_if_local_fini(void)
{
    int i;

    s_net_if_rt_array_offset = 0;

    if (unlikely(0 != s_net_if_rt_cnt)) {
        lune_log(LUNE_WARN, "%d interfaces not deleted while releasing interface resource", s_net_if_rt_cnt);
        for (i = 0; i < LUNE_NET_IF_MAX_NUM; i++) {
            if (unlikely(NULL != s_net_if_rt_array[i])) {
                if (NET_IF_IS_ACTIVE(s_net_if_rt_array[i])) {
                    lune_assert(!net_if_disable_net_if(s_net_if_rt_array[i]));
                }
                (void)net_if_del_net_if(s_net_if_rt_array[i]);
                s_net_if_rt_array[i] = NULL;
            }
        }
    }
}

static int net_if_socket_create(socket_t *sk)
{
    net_if_pcb_t *pcb = &sk->pcb.net_if;

    pcb->cb.recv = NULL;
    pcb->cb.data = NULL;
    pcb->ifp = NULL;

    return 0;
}

static int net_if_socket_bind(socket_t *sk, const void *arg, unsigned int arg_len)
{
    net_if_t *ifp;
    net_if_pcb_t *pcb;

    if (arg_len != sizeof(unsigned int)) {
        return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
    }

    pcb = &sk->pcb.net_if;
    if (NULL != pcb->ifp) {
        return ERR_SET_ERR(LUNE_ERR_ALREADY_BOUND);
    }

    if (NULL == (ifp = net_if_get_net_if_by_id(*(const unsigned int *)arg))) {
        return ERR_SET_ERR(LUNE_ERR_ID_NOT_FOUND);
    }

    if (NET_IF_IS_HOOK(ifp)) {
        return ERR_SET_ERR(LUNE_ERR_NOT_SUPPORTED);
    }

    if (NET_IF_IS_SOCKET(ifp)) {
        return ERR_SET_ERR(LUNE_ERR_ALREADY_BOUND);
    }

    if (!NET_IF_IS_ACTIVE(ifp)) {
        return ERR_SET_ERR(LUNE_ERR_NET_IF_INACTIVE);
    }

    /*
        it is not necessary to net_if_hold(ifp) because ifp cannot be deleted or disabled until socket is close
    */
    pcb->ifp = ifp;

    NET_IF_SET_SOCKET(ifp);
    /*
        it is not necessary to socket_hold(sk) because ifp->sk exists only within the lifetime of socket
    */
    ifp->sk = sk;

    return 0;
}

static int net_if_socket_send(socket_t *sk, const unsigned char *buf, unsigned int len)
{
    net_if_t *ifp = sk->pcb.net_if.ifp;
    int err;

    if (unlikely(NULL == ifp)) {
        return ERR_SET_ERR(LUNE_ERR_NOT_BOUND);
    }

    if (unlikely(!NET_IF_IS_ACTIVE(ifp))) {
        return ERR_SET_ERR(LUNE_ERR_NET_IF_INACTIVE);
    }

    if (ifp->max_tx_data_rate_per_ms != NET_IF_MAX_TX_DATA_RATE_UNLIMITED
        && ifp->tx_rt_data_per_ms >= ifp->max_tx_data_rate_per_ms) {
        return ERR_SET_ERR(LUNE_ERR_EXCEED_LIMITS);
    }

    if (unlikely(!net_if_is_valid_pkt_size(buf, len, ifp))) {
        return ERR_SET_ERR(LUNE_ERR_OVERSIZED_PKT);
    }

    if (0 != (err = ifp->drv->send(ifp->net_if_data, buf, len))) {
        return err;
    }

    ifp->tx_rt_data_per_ms += len;

    /* capture sent packets if enabled */
    NET_IF_CAP_PKT(ifp, buf, len);

    return 0;
}

static int net_if_socket_send_pkts(socket_t *sk,
    lune_socket_send_pkt_t *pkts,
    unsigned int pkt_num,
    unsigned int mode __attribute__((unused)))
{
    net_if_t *ifp = sk->pcb.net_if.ifp;
    unsigned int i;
    int ret;

    if (unlikely(NULL == ifp)) {
        return ERR_SET_ERR(LUNE_ERR_NOT_BOUND);
    }

    if (unlikely(!NET_IF_IS_ACTIVE(ifp))) {
        return ERR_SET_ERR(LUNE_ERR_NET_IF_INACTIVE);
    }

    if (NULL != ifp->drv->send_pkts) {
        if (0 > (ret = ifp->drv->send_pkts(ifp->net_if_data, (net_if_send_pkt_t *)pkts, pkt_num))) {
            /* no packet sent, return error code */
            return ret;
        }

        for (i = 0; i < (unsigned int)ret; i++) {
            ifp->tx_rt_data_per_ms += pkts[i].len;
            /* capture sent packets if enabled */
            NET_IF_CAP_PKT(ifp, pkts[i].buf, pkts[i].len);
        }

        return ret;
    }

    for (i = 0; i < pkt_num; i++) {
        if (likely(net_if_is_valid_pkt_size(pkts[i].buf, pkts[i].len, ifp))) {
            if (0 == (ret = ifp->drv->send(ifp->net_if_data, pkts[i].buf, pkts[i].len))) {
                ifp->tx_rt_data_per_ms += pkts[i].len;
                /* capture sent packets if enabled */
                NET_IF_CAP_PKT(ifp, pkts[i].buf, pkts[i].len);
                continue;
            }
        } else {
            ret = ERR_SET_ERR(LUNE_ERR_OVERSIZED_PKT);
        }

        if (0 == i) {
            /* no packet sent, return error code */
            return ret;
        } else {
            /* return number of sent packets */
            return i;
        }
    }

    return pkt_num;
}

static int net_if_socket_set_opt(socket_t *sk, lune_socket_opt_en opt, unsigned char *opt_val, unsigned int opt_len)
{
    net_if_pcb_t *pcb = &sk->pcb.net_if;

    switch (opt) {
    case LUNE_SOCKET_OPT_SET_CALLBACK:
        if (NULL == opt_val
            || opt_len != sizeof(lune_net_if_socket_callback_t)) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        pcb->cb.recv = ((lune_net_if_socket_callback_t *)opt_val)->recv;
        pcb->cb.data = ((lune_net_if_socket_callback_t *)opt_val)->data;
        break;
    default:
        return ERR_SET_ERR(LUNE_ERR_OPT_NOT_FOUND);
    }

    return 0;
}

static int net_if_socket_close(socket_t *sk)
{
    net_if_t *ifp;
    net_if_pcb_t *pcb = &sk->pcb.net_if;

    pcb->cb.recv = NULL;

    ifp = pcb->ifp;
    if (NULL != ifp) {
        NET_IF_SET_NONSOCK(ifp);
        ifp->sk = NULL;
        pcb->ifp = NULL;
    }

    return 0;
}

socket_ops_t g_socket_ops_net_if = {
    .create = (socket_create_func_t)net_if_socket_create,
    .bind = (socket_bind_func_t)net_if_socket_bind,
    .connect = NULL,
    .listen = NULL,
    .send = (socket_send_func_t)net_if_socket_send,
    .send_pkts = (socket_send_pkts_func_t)net_if_socket_send_pkts,
    .sendto = NULL,
    .get_opt = NULL,
    .set_opt = (socket_set_opt_func_t)net_if_socket_set_opt,
    .close = (socket_close_func_t)net_if_socket_close,
    .hash = NULL,
    .compare = NULL,
    .get_max_hdr_len = NULL,
};

static void net_if_handle_comm_req_add_net_if(const void *val, unsigned int len)
{
    int err = 0;
    const net_if_comm_add_net_if_conf_t *conf;
    unsigned int id, conf_len;
    const void *conf_val;

    if (unlikely(NULL == val || len != sizeof(net_if_comm_add_net_if_conf_t))) {
        err = ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        lune_log(LUNE_INFO, "failed to add interface: %s",
            ERR_GET_ERR_STR(err));
        goto ERR_1;
    }

    conf = (const net_if_comm_add_net_if_conf_t *)val;

    if (LUNE_NET_IF_DPDK == conf->type) {
        conf_val = &conf->dpdk_conf;
        conf_len = sizeof(lune_net_if_dpdk_conf_t);
    } else if (LUNE_NET_IF_DPDK_QUEUE == conf->type) {
        conf_val = &conf->dpdk_queue_conf;
        conf_len = sizeof(lune_net_if_dpdk_queue_conf_t);
    } else {
        conf_val = NULL;
        conf_len = 0;
    }

    if (conf->is_aggr) {
        if (LUNE_INVALID_ID == (id = lune_add_net_if(conf->type,
            conf->name, conf_val, conf_len))) {
            err = ERR_GET_LAST_ERR();
            lune_log(LUNE_INFO, "failed to add interface %s: %s",
                conf->name, ERR_GET_ERR_STR(err));
            goto ERR_1;
        }

        if (0 != (err = lune_set_net_if_opt(id,
            LUNE_NET_IF_OPT_SET_AGGR, &conf->aggr_conf, sizeof(conf->aggr_conf)))) {
            lune_log(LUNE_INFO, "failed to set aggregated interface %s: %s",
                conf->name, ERR_GET_ERR_STR(err));
            goto ERR_2;
        }
    } else {
        if (LUNE_INVALID_ID == (id = lune_add_net_if(conf->type,
            conf->name, conf_val, conf_len))) {
            err = ERR_GET_LAST_ERR();
            lune_log(LUNE_INFO, "failed to add interface %s: %s",
                conf->name, ERR_GET_ERR_STR(err));
            goto ERR_1;
        }
    }

    if (0 != (err = comm_core_send_resp(LUNE_COMM_RESP_ADD_NET_IF, &id, sizeof(id), err))) {
        lune_log(LUNE_INFO, "failed to send response to add interface %s: %s",
            conf->name, ERR_GET_ERR_STR(err));
    }

    return;

ERR_2:
    lune_assert(!lune_del_net_if(id));

ERR_1:
    if (0 != (err = comm_core_send_resp(LUNE_COMM_RESP_ADD_NET_IF, NULL, 0, err))) {
        lune_log(LUNE_INFO, "failed to send response to add interface: %s",
            ERR_GET_ERR_STR(err));
    }
}

static void net_if_handle_comm_req_del_net_if(const void *val, unsigned int len)
{
    int err;
    unsigned int id;

    if (unlikely(NULL == val || len != sizeof(net_if_comm_del_net_if_conf_t))) {
        err = ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        lune_log(LUNE_INFO, "failed to delete interface: %s",
            ERR_GET_ERR_STR(err));
        if (0 != (err = comm_core_send_resp(LUNE_COMM_RESP_DEL_NET_IF, NULL, 0, err))) {
            lune_log(LUNE_INFO, "failed to send response to delete interface: %s",
                ERR_GET_ERR_STR(err));
        }
        return;
    }

    id = ((const net_if_comm_del_net_if_conf_t *)val)->id;
    if (0 != (err = lune_del_net_if(id))) {
        lune_log(LUNE_INFO, "failed to delete interface %08x: %s",
            id, ERR_GET_ERR_STR(err));
        goto ERR;
    }

    if (0 != (err = comm_core_send_resp(LUNE_COMM_RESP_DEL_NET_IF, NULL, 0, err))) {
        lune_log(LUNE_INFO, "failed to send response to delete interface %08x: %s",
            id, ERR_GET_ERR_STR(err));
    }

    return;

ERR:
    if (0 != (err = comm_core_send_resp(LUNE_COMM_RESP_DEL_NET_IF, NULL, 0, err))) {
        lune_log(LUNE_INFO, "failed to send response to delete interface %08x: %s",
            id, ERR_GET_ERR_STR(err));
    }
}

static void net_if_handle_comm_req_enable_net_if(const void *val, unsigned int len)
{
    int err;
    unsigned int id;

    if (unlikely(NULL == val || len != sizeof(net_if_comm_enable_net_if_conf_t))) {
        err = ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        lune_log(LUNE_INFO, "failed to enable interface: %s",
            ERR_GET_ERR_STR(err));
        if (0 != (err = comm_core_send_resp(LUNE_COMM_RESP_ENABLE_NET_IF, NULL, 0, err))) {
            lune_log(LUNE_INFO, "failed to send response to enable interface: %s",
                ERR_GET_ERR_STR(err));
        }
        return;
    }

    id = ((const net_if_comm_enable_net_if_conf_t *)val)->id;
    if (0 != (err = lune_enable_net_if(id))) {
        err = ERR_GET_LAST_ERR();
        lune_log(LUNE_INFO, "failed to enable interface %08x: %s",
            id, ERR_GET_ERR_STR(err));
        goto ERR;
    }

    if (0 != (err = comm_core_send_resp(LUNE_COMM_RESP_ENABLE_NET_IF, NULL, 0, err))) {
        lune_log(LUNE_INFO, "failed to send response to enable interface %08x: %s",
            id, ERR_GET_ERR_STR(err));
    }

    return;

ERR:
    if (0 != (err = comm_core_send_resp(LUNE_COMM_RESP_ENABLE_NET_IF, NULL, 0, err))) {
        lune_log(LUNE_INFO, "failed to send response to enable interface %08x: %s",
            id, ERR_GET_ERR_STR(err));
    }
}

static void net_if_handle_comm_req_disable_net_if(const void *val, unsigned int len)
{
    int err;
    unsigned int id;

    if (unlikely(NULL == val || len != sizeof(net_if_comm_disable_net_if_conf_t))) {
        err = ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        lune_log(LUNE_INFO, "failed to disable interface: %s",
            ERR_GET_ERR_STR(err));
        if (0 != (err = comm_core_send_resp(LUNE_COMM_RESP_DISABLE_NET_IF, NULL, 0, err))) {
            lune_log(LUNE_INFO, "failed to send response to disable interface: %s",
                ERR_GET_ERR_STR(err));
        }
        return;
    }

    id = ((const net_if_comm_disable_net_if_conf_t *)val)->id;
    if (0 != (err = lune_disable_net_if(id))) {
        err = ERR_GET_LAST_ERR();
        lune_log(LUNE_INFO, "failed to disable interface %08x: %s",
            id, ERR_GET_ERR_STR(err));
        goto ERR;
    }

    if (0 != (err = comm_core_send_resp(LUNE_COMM_RESP_DISABLE_NET_IF, NULL, 0, err))) {
        lune_log(LUNE_INFO, "failed to send response to disable interface %08x: %s",
            id, ERR_GET_ERR_STR(err));
    }

    return;

ERR:
    if (0 != (err = comm_core_send_resp(LUNE_COMM_RESP_DISABLE_NET_IF, NULL, 0, err))) {
        lune_log(LUNE_INFO, "failed to send response to disable interface %08x: %s",
            id, ERR_GET_ERR_STR(err));
    }
}

static void net_if_handle_comm_req_get_net_if_opt(const void *val, unsigned int len)
{
    int err;
    const net_if_comm_get_net_if_opt_conf_t *conf;

    if (unlikely(NULL == val || len != sizeof(net_if_comm_get_net_if_opt_conf_t))) {
        err = ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        lune_log(LUNE_INFO, "failed to set option of interface: %s",
            ERR_GET_ERR_STR(err));
        if (0 != (err = comm_core_send_resp(LUNE_COMM_RESP_GET_NET_IF_OPT, NULL, 0, err))) {
            lune_log(LUNE_INFO, "failed to send response to set option of interface: %s",
                ERR_GET_ERR_STR(err));
        }
        return;
    }

    conf = (const net_if_comm_get_net_if_opt_conf_t *)val;
    if (0 != (err = lune_get_net_if_opt(conf->id, conf->opt, conf->opt_val, conf->opt_len))) {
        err = ERR_GET_LAST_ERR();
        lune_log(LUNE_INFO, "failed to set option %d of interface %08x: %s",
            conf->opt, conf->id, ERR_GET_ERR_STR(err));
    }

    if (0 != (err = comm_core_send_resp(LUNE_COMM_RESP_GET_NET_IF_OPT, NULL, 0, err))) {
        lune_log(LUNE_INFO, "failed to send response to set option %d of interface %08x: %s",
            conf->opt, conf->id, ERR_GET_ERR_STR(err));
    }
}

static void net_if_handle_comm_req_set_net_if_opt(const void *val, unsigned int len)
{
    int err;
    const net_if_comm_set_net_if_opt_conf_t *conf;

    if (unlikely(NULL == val || len != sizeof(net_if_comm_set_net_if_opt_conf_t))) {
        err = ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        lune_log(LUNE_INFO, "failed to set option of interface: %s",
            ERR_GET_ERR_STR(err));
        if (0 != (err = comm_core_send_resp(LUNE_COMM_RESP_SET_NET_IF_OPT, NULL, 0, err))) {
            lune_log(LUNE_INFO, "failed to send response to set option of interface: %s",
                ERR_GET_ERR_STR(err));
        }
        return;
    }

    conf = (const net_if_comm_set_net_if_opt_conf_t *)val;
    if (0 != (err = lune_set_net_if_opt(conf->id, conf->opt, conf->opt_val, conf->opt_len))) {
        err = ERR_GET_LAST_ERR();
        lune_log(LUNE_INFO, "failed to set option %d of interface %08x: %s",
            conf->opt, conf->id, ERR_GET_ERR_STR(err));
    }

    if (0 != (err = comm_core_send_resp(LUNE_COMM_RESP_SET_NET_IF_OPT, NULL, 0, err))) {
        lune_log(LUNE_INFO, "failed to send response to set option %d of interface %08x: %s",
            conf->opt, conf->id, ERR_GET_ERR_STR(err));
    }
}

static void net_if_handle_comm_req_connect_net_if(const void *val, unsigned int len)
{
    int err;
    const net_if_comm_connect_net_if_conf_t *conf;

    if (unlikely(NULL == val || len != sizeof(net_if_comm_connect_net_if_conf_t))) {
        err = ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        lune_log(LUNE_INFO, "failed to connect interface: %s",
            ERR_GET_ERR_STR(err));
        if (0 != (err = comm_core_send_resp(LUNE_COMM_RESP_CONNECT_NET_IF, NULL, 0, err))) {
            lune_log(LUNE_INFO, "failed to send response to connect interface: %s",
                ERR_GET_ERR_STR(err));
        }
        return;
    }

    conf = (const net_if_comm_connect_net_if_conf_t *)val;

    if (conf->peer_core_id == (unsigned int)CORE_GET_ID()) {
        /* connect local interfaces */
        if (0 != (err = net_if_connect_local_net_if(conf->id, conf->peer_id))) {
            goto ERR;
        }
    } else {
        /* connect local interface with interface on another core */
        if (0 != (err = net_if_connect_remote_net_if(conf->id, conf->peer_id, conf->peer_core_id))) {
            goto ERR;
        }
    }

    if (0 != (err = comm_core_send_resp(LUNE_COMM_RESP_CONNECT_NET_IF, NULL, 0, err))) {
        goto ERR;
    }

    return;

ERR:
    if (0 != (err = comm_core_send_resp(LUNE_COMM_RESP_CONNECT_NET_IF, NULL, 0, err))) {
        lune_log(LUNE_INFO, "failed to send response to connect interface %08x to interface %08x: %s",
            conf->id, conf->peer_id, ERR_GET_ERR_STR(err));
    }
}

static void net_if_handle_comm_req_disconnect_net_if(const void *val, unsigned int len)
{
    int err;
    const net_if_comm_disconnect_net_if_conf_t *conf;

    if (unlikely(NULL == val || len != sizeof(net_if_comm_disconnect_net_if_conf_t))) {
        err = ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        lune_log(LUNE_INFO, "failed to disconnect interface: %s",
            ERR_GET_ERR_STR(err));
        if (0 != (err = comm_core_send_resp(LUNE_COMM_RESP_DISCONNECT_NET_IF, NULL, 0, err))) {
            lune_log(LUNE_INFO, "failed to send response to disconnect interface: %s",
                ERR_GET_ERR_STR(err));
        }
        return;
    }

    conf = (const net_if_comm_disconnect_net_if_conf_t *)val;

    if (0 != (err = net_if_disconnect_net_if(conf->id))) {
        goto ERR;
    }

    if (0 != (err = comm_core_send_resp(LUNE_COMM_RESP_DISCONNECT_NET_IF, NULL, 0, err))) {
        goto ERR;
    }

    return;

ERR:
    if (0 != (err = comm_core_send_resp(LUNE_COMM_RESP_DISCONNECT_NET_IF, NULL, 0, err))) {
        lune_log(LUNE_INFO, "failed to send response to disconnect interface %08x: %s",
            conf->id, ERR_GET_ERR_STR(err));
    }
}

COMM_REQ_HANDLER_DECL(ADD_NET_IF, net_if_handle_comm_req_add_net_if)
COMM_REQ_HANDLER_DECL(DEL_NET_IF, net_if_handle_comm_req_del_net_if)
COMM_REQ_HANDLER_DECL(ENABLE_NET_IF, net_if_handle_comm_req_enable_net_if)
COMM_REQ_HANDLER_DECL(DISABLE_NET_IF, net_if_handle_comm_req_disable_net_if)
COMM_REQ_HANDLER_DECL(GET_NET_IF_OPT, net_if_handle_comm_req_get_net_if_opt)
COMM_REQ_HANDLER_DECL(SET_NET_IF_OPT, net_if_handle_comm_req_set_net_if_opt)
COMM_REQ_HANDLER_DECL(CONNECT_NET_IF, net_if_handle_comm_req_connect_net_if)
COMM_REQ_HANDLER_DECL(DISCONNECT_NET_IF, net_if_handle_comm_req_disconnect_net_if)

NET_IF_DRIVER_DECL(LUNE_NET_IF_CHAN, g_net_if_drv_chan);
#ifdef LUNE_BUILD_DPDK
extern net_if_drv_t g_net_if_drv_dpdk;
NET_IF_DRIVER_DECL(LUNE_NET_IF_DPDK, g_net_if_drv_dpdk);
NET_IF_DRIVER_DECL(LUNE_NET_IF_DPDK_CHAN, g_net_if_drv_dpdk_chan);
NET_IF_DRIVER_DECL(LUNE_NET_IF_DPDK_QUEUE, g_net_if_drv_dpdk_queue)
NET_IF_DRIVER_DECL(LUNE_NET_IF_DPDK_QUEUE_CHAN, g_net_if_drv_dpdk_queue_chan);
#endif
NET_IF_DRIVER_DECL(LUNE_NET_IF_STD, g_net_if_drv_std);
NET_IF_DRIVER_DECL(LUNE_NET_IF_VIRT, g_net_if_drv_virt);
