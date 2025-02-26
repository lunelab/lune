/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2024 Lune Reseau, Inc.
 *
 * Lune Test Tcp Perf tool
 */

#include <yaml.h>

#include "lune/arp.h"
#include "lune/assert.h"
#include "lune/atomic.h"
#include "lune/err.h"
#include "lune/init.h"
#include "lune/ip.h"
#include "lune/core.h"
#include "lune/log.h"
#include "lune/mac.h"
#include "lune/mem.h"
#include "lune/net_if.h"
#include "lune/os/linux.h"
#include "lune/sched.h"
#include "lune/ssl.h"
#include "lune/tcp.h"
#include "lune/time.h"
#include "lune/timer.h"

#include "ttp/ssl.h"
#include "ttp/ttp.h"

#if __GNUC__ >=7
#pragma GCC diagnostic ignored "-Wformat-overflow"
#endif

#define TTP_NA_IS_CLIENT(type)              \
    ((LUNE_NET_IF_AGGR_MAC_CLIENT == (type)) || (LUNE_NET_IF_AGGR_IP_CLIENT == (type)))

#define TTP_CPU_LIST_MAX_BUF_LEN            (256)
#define TTP_CLIENT_IP_NUM                   (1024)
#define TTP_CLIENT_START_MAC                ("00:10:00:00:00:00")
#define TTP_CLIENT_END_MAC                  ("00:10:00:00:03:ff")
#define TTP_CLIENT_START_IPV4               ("1.0.0.0")
#define TTP_CLIENT_END_IPV4                 ("1.0.3.255")
#define TTP_CLIENT_START_IPV6               ("2001:500:100::000")
#define TTP_CLIENT_END_IPV6                 ("2001:500:100::3ff")
#define TTP_CLIENT_START_PORT               (1024)
#define TTP_CLIENT_END_PORT                 (60000)
#define TTP_SERVER_MAC                      ("00:10:00:00:04:00")
#define TTP_SERVER_IPV4                     ("1.0.4.0")
#define TTP_SERVER_IPV6                     ("2001:500:100::400")
#define TTP_SERVER_PORT                     (1000)
#define TTP_CLIENT_MASK                     ("255.255.0.0")
#define TTP_CLIENT_GW                       ("1.0.5.0")
#define TTP_PRE_RUN_TIME_IN_SEC             (5)
#define TTP_POST_RUN_TIME_IN_SEC            (5)
#define TTP_AGGR_MAX_NA_NUM                 (8)
#define TTP_AGGR_MAX_NP_NUM                 (32)
#define TTP_AGGR_MAX_CP_NUM                 (TTP_AGGR_MAX_NP_NUM)
#define TTP_MAX_PAYLOAD_LEN                 (1460)

/* ttp parser section state */
#define TTP_PSS_CPU_STR                     "cpu"
#define TTP_PSS_CPU_NRT_STR                 "nrt"
#define TTP_PSS_CPU_RT_CLIENT_START_STR     "rt_client_start"
#define TTP_PSS_CPU_RT_CLIENT_NA_NUM_STR    "rt_client_na_num"
#define TTP_PSS_CPU_RT_CLIENT_NP_NUM_STR    "rt_client_np_num"
#define TTP_PSS_CPU_RT_CLIENT_CP_NUM_STR    "rt_client_cp_num"
#define TTP_PSS_CPU_RT_SERVER_START_STR     "rt_server_start"
#define TTP_PSS_CPU_RT_SERVER_NA_NUM_STR    "rt_server_na_num"
#define TTP_PSS_CPU_RT_SERVER_NP_NUM_STR    "rt_server_np_num"
#define TTP_PSS_CPU_RT_SERVER_CP_NUM_STR    "rt_server_cp_num"

#define TTP_PSS_NET_IF_STR                  "interface"
#define TTP_PSS_NET_IF_CLIENT_STR           "client"
#define TTP_PSS_NET_IF_CLIENT_NAME_STR      "name"
#define TTP_PSS_NET_IF_CLIENT_TYPE_STR      "type"
#define TTP_PSS_NET_IF_CLIENT_CAPTURE_STR   "capture"
#define TTP_PSS_NET_IF_SERVER_STR           "server"
#define TTP_PSS_NET_IF_SERVER_NAME_STR      "name"
#define TTP_PSS_NET_IF_SERVER_TYPE_STR      "type"
#define TTP_PSS_NET_IF_SERVER_CAPTURE_STR   "capture"

#define TTP_PSS_LOAD_STR                    "load"
#define TTP_PSS_LOAD_TIME_STR               "time"
#define TTP_PSS_LOAD_RATE_STR               "rate"
#define TTP_PSS_LOAD_PAYLOAD_LEN_STR        "payload_len"
#define TTP_PSS_LOAD_PKT_CNT_STR            "pkt_cnt"
#define TTP_PSS_LOAD_MAX_CC_STR             "max_cc"
#define TTP_PSS_LOAD_PKT_INTVL_STR          "pkt_intvl"
#define TTP_PSS_LOAD_SSL_STR                "ssl"
#define TTP_PSS_LOAD_IP_STR                 "ip"

#define TTP_NET_IF_STD_STR                  "standard"
#define TTP_NET_IF_DPDK_STR                 "dpdk"
#define TTP_NET_IF_DPDK_QUEUE_STR           "dpdk_queue"
#define TTP_NET_IF_VIRT_STR                 "virtual"

#define TTP_OPTION_IPV4_STR                 "ipv4"
#define TTP_OPTION_IPV6_STR                 "ipv6"

#define TTP_OPTION_ENABLE_STR               "enable"
#define TTP_OPTION_DISABLE_STR              "disable"

#define TTP_LOAD_SSL_VER_NONE_STR           "none"
#define TTP_LOAD_SSL_VER_TLS_1_2_STR        "tls1.2"
#define TTP_LOAD_SSL_VER_TLS_1_3_STR        "tls1.3"

/* ttp configuration */
typedef struct _ttp_conf {
    struct {
        unsigned int nrt;
        unsigned int rt_client_start;
        unsigned int rt_client_na_num;
        unsigned int rt_client_np_num;
        unsigned int rt_client_cp_num;
        unsigned int rt_server_start;
        unsigned int rt_server_na_num;
        unsigned int rt_server_np_num;
        unsigned int rt_server_cp_num;
    } cpu;
    struct {
        struct {
            char name[LUNE_MAX_NAME_BUF_LEN];
            lune_net_if_type_en type;
            unsigned int cap_enable;
        } client;
        struct {
            char name[LUNE_MAX_NAME_BUF_LEN];
            lune_net_if_type_en type;
            unsigned int cap_enable;
        } server;
    } net_if;
    struct {
        unsigned int time;  /* in second */
        unsigned int rate;
        unsigned int rate_per_core;
        unsigned int payload_len;
        unsigned int pkt_cnt;
        unsigned int max_cc;
        unsigned int max_cc_per_core;
        unsigned int pkt_intvl;
#define TTP_LOAD_SSL_VER_NONE               (0)
#define TTP_LOAD_SSL_VER_TLS_1_2            (1)
#define TTP_LOAD_SSL_VER_TLS_1_3            (2)
        unsigned int ssl_ver;
        unsigned int is_ipv6;
    } load;
} ttp_conf_t;

/* ttp parser state */
typedef enum _ttp_parser_state {
    TTP_PS_START,
    TTP_PS_ACCEPT_SECTION,
    TTP_PS_ACCEPT_LIST,
    TTP_PS_ACCEPT_KEY,
    TTP_PS_ACCEPT_VALUE,
    TTP_PS_STOP,
    TTP_PS_ERROR,
} ttp_parser_state_en;

typedef enum _ttp_parser_section_state {
    TTP_PSS_CPU,
    TTP_PSS_NET_IF,
    TTP_PSS_NET_IF_CLIENT,
    TTP_PSS_NET_IF_SERVER,
    TTP_PSS_LOAD,
    TTP_PSS_NONE,
} ttp_parser_section_state_en;

typedef struct _ttp_parser_ins {
    ttp_parser_state_en state;
    ttp_parser_section_state_en sstate;
    int accepted;
    int error;
    char *key;
    char *value;
} ttp_parser_ins_t;

static ttp_conf_t s_ttp_conf;
static __thread ttp_conf_t s_ttp_local_conf;

typedef struct _ttp_socket {
    unsigned int socket_id;
    unsigned int pkt_cnt;
    lune_timer_t tmr;
} ttp_socket_t;

static __thread unsigned int s_ttp_np_net_if_id;
static __thread unsigned int s_ttp_np_ssl_id;
static __thread unsigned int s_ttp_np_mac_id_array[TTP_CLIENT_IP_NUM];
static __thread unsigned int s_ttp_np_ip_id_array[TTP_CLIENT_IP_NUM];
static __thread unsigned int s_ttp_np_ip_id_cnt;
static __thread unsigned int s_ttp_np_ip_id_offset;
static __thread unsigned int s_ttp_np_start_port;
static __thread unsigned int s_ttp_np_end_port;
static __thread unsigned int s_ttp_np_port_offset;
static __thread unsigned int s_ttp_np_client_run_task_id;
/* quotient */
static __thread unsigned int s_ttp_np_client_conn_per_tick_q;
/* remainder */
static __thread float s_ttp_np_client_conn_per_tick_r;
static __thread float s_ttp_np_client_conn_accum_r;
static __thread unsigned int s_ttp_np_server_socket_id;
static __thread lune_ip_addr_t s_ttp_np_server_ip;
static __thread unsigned int s_ttp_np_init_task_id;
static __thread void *s_ttp_np_socket_mem_pool;

static __thread unsigned char s_ttp_payload_buf[TTP_MAX_PAYLOAD_LEN] = {0};
static __thread lune_timer_t s_ttp_np_tmr;
static __thread unsigned int s_ttp_concurrent_socket_cnt;

static unsigned int s_ttp_client_net_if_enable_flag;
static unsigned int s_ttp_server_net_if_enable_flag;
static unsigned int s_ttp_start_flag;
static unsigned int s_ttp_stop_flag;

static int s_ttp_client_np_id[TTP_AGGR_MAX_NP_NUM];
static int s_ttp_client_na_id[TTP_AGGR_MAX_NA_NUM];
static int s_ttp_client_cp_id[TTP_AGGR_MAX_CP_NUM];
static unsigned int s_ttp_client_net_if_id;
static int s_ttp_server_np_id[TTP_AGGR_MAX_NP_NUM];
static int s_ttp_server_na_id[TTP_AGGR_MAX_NA_NUM];
static int s_ttp_server_cp_id[TTP_AGGR_MAX_CP_NUM];
static unsigned int s_ttp_server_net_if_id;

/*
 *
 *    stream-start-event
 *      document-start-event
 *        mapping-start-event
 *          scalar-event={value="cpu", length=x}
 *          mapping-start-event
 *            scalar-event={value="nrt", length=x}
 *            scalar-event={value="x", length=x}
 *            scalar-event={value="rt_client_start", length=x}
 *            scalar-event={value="x", length=x}
 *            ...
 *          mapping-end-event
 *        mapping-end-event
 *        mapping-start-event
 *          scalar-event={value="net_if", length=x}
 *          mapping-start-event
 *            scalar-event={value="client", length=x}
 *            mapping-start-event
 *              scalar-event={value="name", length=x}
 *              scalar-event={value="x", length=x}
 *              scalar-event={value="type", length=x}
 *              scalar-event={value="x", length=x}
 *            mapping-end-event
 *          mapping-end-event
 *          mapping-start-event
 *            scalar-event={value="server", length=x}
 *            mapping-start-event
 *              scalar-event={value="name", length=x}
 *              scalar-event={value="x", length=x}
 *              scalar-event={value="type", length=x}
 *              scalar-event={value="x", length=x}
 *            mapping-end-event
 *          mapping-end-event
 *        mapping-end-event
 *        ...
 *      document-end-event
 *    stream-end-event
 *
 */

static int ttp_process_cpu_event(ttp_parser_ins_t *pi, yaml_event_t *ev)
{
    if (!strcmp(pi->key, TTP_PSS_CPU_NRT_STR)) {
        s_ttp_conf.cpu.nrt = atoi(pi->value);
    } else if (!strcmp(pi->key, TTP_PSS_CPU_RT_CLIENT_START_STR)) {
        s_ttp_conf.cpu.rt_client_start = atoi(pi->value);
    } else if (!strcmp(pi->key, TTP_PSS_CPU_RT_CLIENT_NA_NUM_STR)) {
        s_ttp_conf.cpu.rt_client_na_num = atoi(pi->value);
    } else if (!strcmp(pi->key, TTP_PSS_CPU_RT_CLIENT_NP_NUM_STR)) {
        s_ttp_conf.cpu.rt_client_np_num = atoi(pi->value);
    } else if (!strcmp(pi->key, TTP_PSS_CPU_RT_CLIENT_CP_NUM_STR)) {
        s_ttp_conf.cpu.rt_client_cp_num = atoi(pi->value);
    } else if (!strcmp(pi->key, TTP_PSS_CPU_RT_SERVER_START_STR)) {
        s_ttp_conf.cpu.rt_server_start = atoi(pi->value);
    } else if (!strcmp(pi->key, TTP_PSS_CPU_RT_SERVER_NA_NUM_STR)) {
        s_ttp_conf.cpu.rt_server_na_num = atoi(pi->value);
    } else if (!strcmp(pi->key, TTP_PSS_CPU_RT_SERVER_NP_NUM_STR)) {
        s_ttp_conf.cpu.rt_server_np_num = atoi(pi->value);
    } else if (!strcmp(pi->key, TTP_PSS_CPU_RT_SERVER_CP_NUM_STR)) {
        s_ttp_conf.cpu.rt_server_cp_num = atoi(pi->value);
    } else {
        fprintf(stderr, "unknown key: %s\n", pi->key);
        pi->state = TTP_PS_ERROR;
        free(pi->key);
        return 0;
    }

    pi->state = TTP_PS_ACCEPT_KEY;

    free(pi->key);
    return 0;
}

static lune_net_if_type_en ttp_convert_net_if_type(const char *type)
{
    if (!strcmp(type, TTP_NET_IF_STD_STR)) {
        return LUNE_NET_IF_STD;
    } else if (!strcmp(type, TTP_NET_IF_DPDK_STR)) {
        return LUNE_NET_IF_DPDK;
    } else if (!strcmp(type, TTP_NET_IF_DPDK_QUEUE_STR)) {
        return LUNE_NET_IF_DPDK_QUEUE;
    } else if (!strcmp(type, TTP_NET_IF_VIRT_STR)) {
        return LUNE_NET_IF_VIRT;
    } else {
        fprintf(stderr, "unknown interface type: %s\n", type);
        return LUNE_NET_IF_MAX;
    }
}

static int ttp_process_net_if_event(ttp_parser_ins_t *pi, yaml_event_t *ev)
{
    switch (pi->sstate) {
    case TTP_PSS_NET_IF:
        if (!strcmp((char*)ev->data.scalar.value, TTP_PSS_NET_IF_CLIENT_STR)) {
            pi->state = TTP_PS_ACCEPT_LIST;
            pi->sstate = TTP_PSS_NET_IF_CLIENT;
        } else if (!strcmp((char*)ev->data.scalar.value, TTP_PSS_NET_IF_SERVER_STR)) {
            pi->state = TTP_PS_ACCEPT_LIST;
            pi->sstate = TTP_PSS_NET_IF_SERVER;
        } else {
            fprintf(stderr, "unexpected scalar: %s\n", (char*)ev->data.scalar.value);
            pi->state = TTP_PS_ERROR;
        }
        break;
    case TTP_PSS_NET_IF_CLIENT:
        if (TTP_PS_ACCEPT_KEY == pi->state) {
            pi->state = TTP_PS_ACCEPT_VALUE;
            break;
        }

        if (!strcmp(pi->key, TTP_PSS_NET_IF_CLIENT_NAME_STR)) {
            strcpy(s_ttp_conf.net_if.client.name, pi->value);
        } else if (!strcmp(pi->key, TTP_PSS_NET_IF_CLIENT_TYPE_STR)) {
            s_ttp_conf.net_if.client.type = ttp_convert_net_if_type(pi->value);
        } else if (!strcmp(pi->key, TTP_PSS_NET_IF_CLIENT_CAPTURE_STR)) {
            if (!strcmp(pi->value, TTP_OPTION_ENABLE_STR)) {
                s_ttp_conf.net_if.client.cap_enable = 1;
            } else if (!strcmp(pi->value, TTP_OPTION_DISABLE_STR)) {
                s_ttp_conf.net_if.client.cap_enable = 0;
            } else {
                fprintf(stderr, "invalid capture option: %s\n", pi->value);
                pi->state = TTP_PS_ERROR;
                break;
            }
        } else {
            fprintf(stderr, "unknown key: %s\n", pi->key);
            pi->state = TTP_PS_ERROR;
            break;
        }

        pi->state = TTP_PS_ACCEPT_KEY;
        break;
    case TTP_PSS_NET_IF_SERVER:
        if (TTP_PS_ACCEPT_KEY == pi->state) {
            pi->state = TTP_PS_ACCEPT_VALUE;
            break;
        }

        if (!strcmp(pi->key, TTP_PSS_NET_IF_SERVER_NAME_STR)) {
            strcpy(s_ttp_conf.net_if.server.name, pi->value);
        } else if (!strcmp(pi->key, TTP_PSS_NET_IF_SERVER_TYPE_STR)) {
            s_ttp_conf.net_if.server.type = ttp_convert_net_if_type(pi->value);
        } else if (!strcmp(pi->key, TTP_PSS_NET_IF_SERVER_CAPTURE_STR)) {
            if (!strcmp(pi->value, TTP_OPTION_ENABLE_STR)) {
                s_ttp_conf.net_if.server.cap_enable = 1;
            } else if (!strcmp(pi->value, TTP_OPTION_DISABLE_STR)) {
                s_ttp_conf.net_if.server.cap_enable = 0;
            } else {
                fprintf(stderr, "invalid capture option: %s\n", pi->value);
                pi->state = TTP_PS_ERROR;
                break;
            }
        } else {
            fprintf(stderr, "unknown key: %s\n", pi->key);
            pi->state = TTP_PS_ERROR;
            break;
        }

        pi->state = TTP_PS_ACCEPT_KEY;
        break;
    default:
        fprintf(stderr, "unknown key: %s\n", pi->key);
        pi->state = TTP_PS_ERROR;
        break;
    }

    free(pi->key);
    return 0;
}

static int ttp_process_load_event(ttp_parser_ins_t *pi, yaml_event_t *ev)
{
    if (!strcmp(pi->key, TTP_PSS_LOAD_TIME_STR)) {
        s_ttp_conf.load.time = atoi(pi->value);
    } else if (!strcmp(pi->key, TTP_PSS_LOAD_RATE_STR)) {
        s_ttp_conf.load.rate = atoi(pi->value);
    } else if (!strcmp(pi->key, TTP_PSS_LOAD_PAYLOAD_LEN_STR)) {
        s_ttp_conf.load.payload_len = atoi(pi->value);
        if (s_ttp_conf.load.payload_len > TTP_MAX_PAYLOAD_LEN) {
            fprintf(stderr, "invalid payload size: %s\n", pi->value);
            return 0;
        }
    } else if (!strcmp(pi->key, TTP_PSS_LOAD_PKT_CNT_STR)) {
        s_ttp_conf.load.pkt_cnt = atoi(pi->value);
    } else if (!strcmp(pi->key, TTP_PSS_LOAD_MAX_CC_STR)) {
        s_ttp_conf.load.max_cc = atoi(pi->value);
    } else if (!strcmp(pi->key, TTP_PSS_LOAD_PKT_INTVL_STR)) {
        s_ttp_conf.load.pkt_intvl = atoi(pi->value);
    } else if (!strcmp(pi->key, TTP_PSS_LOAD_SSL_STR)) {
        if (!strcmp(pi->value, TTP_LOAD_SSL_VER_NONE_STR)) {
            s_ttp_conf.load.ssl_ver = TTP_LOAD_SSL_VER_NONE;
        } else if (!strcmp(pi->value, TTP_LOAD_SSL_VER_TLS_1_2_STR)) {
            s_ttp_conf.load.ssl_ver = TTP_LOAD_SSL_VER_TLS_1_2;
        } else if (!strcmp(pi->value, TTP_LOAD_SSL_VER_TLS_1_3_STR)) {
            s_ttp_conf.load.ssl_ver = TTP_LOAD_SSL_VER_TLS_1_3;
        } else {
            fprintf(stderr, "invalid ssl option: %s\n", pi->value);
            return 0;
        }
    } else if (!strcmp(pi->key, TTP_PSS_LOAD_IP_STR)) {
        if (!strcmp(pi->value, TTP_OPTION_IPV4_STR)) {
            s_ttp_conf.load.is_ipv6 = 0;
        } else if (!strcmp(pi->value, TTP_OPTION_IPV6_STR)) {
            s_ttp_conf.load.is_ipv6 = 1;
        } else {
            fprintf(stderr, "invalid ip option: %s\n", pi->value);
            return 0;
        }
    } else {
        fprintf(stderr, "unknown key: %s\n", pi->key);
        pi->state = TTP_PS_ERROR;
        free(pi->key);
        return 0;
    }

    pi->state = TTP_PS_ACCEPT_KEY;

    free(pi->key);
    return 0;
}

static int ttp_process_event(ttp_parser_ins_t *pi, yaml_event_t *ev)
{
    pi->accepted = 0;
    switch (pi->state) {
    case TTP_PS_START:
        switch (ev->type) {
        case YAML_MAPPING_START_EVENT:
            pi->state = TTP_PS_ACCEPT_SECTION;
            break;
        case YAML_SCALAR_EVENT:
            fprintf(stderr, "unexpected scalar: %s\n", (char*)ev->data.scalar.value);
            pi->state = TTP_PS_ERROR;
            break;
        case YAML_STREAM_END_EVENT:
            pi->state = TTP_PS_STOP;
            break;
        default:
            break;
        }
        break;
    case TTP_PS_ACCEPT_SECTION:
        switch (ev->type) {
        case YAML_SCALAR_EVENT:
            if (!strcmp((char*)ev->data.scalar.value, TTP_PSS_CPU_STR)) {
                pi->state = TTP_PS_ACCEPT_LIST;
                pi->sstate = TTP_PSS_CPU;
            } else if (!strcmp((char*)ev->data.scalar.value, TTP_PSS_NET_IF_STR)) {
                pi->state = TTP_PS_ACCEPT_LIST;
                pi->sstate = TTP_PSS_NET_IF;
            } else if (!strcmp((char*)ev->data.scalar.value, TTP_PSS_LOAD_STR)) {
                pi->state = TTP_PS_ACCEPT_LIST;
                pi->sstate = TTP_PSS_LOAD;
            } else {
                fprintf(stderr, "unexpected scalar: %s\n", (char*)ev->data.scalar.value);
                pi->state = TTP_PS_ERROR;
            }
            break;
        case YAML_MAPPING_END_EVENT:
            break;
        case YAML_DOCUMENT_END_EVENT:
            pi->accepted = 1;
            pi->state = TTP_PS_START;
            break;
        default:
            fprintf(stderr, "unexpected event while getting scalar: %d\n", ev->type);
            pi->state = TTP_PS_ERROR;
            break;
        }
        break;
    case TTP_PS_ACCEPT_LIST:
        switch (ev->type) {
        case YAML_MAPPING_START_EVENT:
            pi->state = TTP_PS_ACCEPT_KEY;
            break;
        default:
            fprintf(stderr, "unexpected event while getting list: %d\n", ev->type);
            pi->state = TTP_PS_ERROR;
            break;
        }
        break;
    case TTP_PS_ACCEPT_KEY:
        switch (ev->type) {
        case YAML_SCALAR_EVENT:
            pi->key = strdup((char*)ev->data.scalar.value);
            switch (pi->sstate) {
            case TTP_PSS_CPU:
            case TTP_PSS_NET_IF_CLIENT:
            case TTP_PSS_NET_IF_SERVER:
            case TTP_PSS_LOAD:
                pi->state = TTP_PS_ACCEPT_VALUE;
                break;
            case TTP_PSS_NET_IF:
                (void)ttp_process_net_if_event(pi, ev);
                break;
            default:
                fprintf(stderr, "unexpected event while getting key: %d\n", ev->type);
                pi->state = TTP_PS_ERROR;
                break;
            }
            break;
        case YAML_MAPPING_END_EVENT:
            switch (pi->sstate) {
            case TTP_PSS_CPU:
            case TTP_PSS_NET_IF:
            case TTP_PSS_LOAD:
                pi->state = TTP_PS_ACCEPT_SECTION;
                break;
            case TTP_PSS_NET_IF_CLIENT:
            case TTP_PSS_NET_IF_SERVER:
                pi->state = TTP_PS_ACCEPT_KEY;
                pi->sstate = TTP_PSS_NET_IF;
                break;
            default:
                fprintf(stderr, "unexpected event while getting key: %d\n", ev->type);
                pi->state = TTP_PS_ERROR;
                break;
            }
            break;
        default:
            fprintf(stderr, "unexpected event while getting key: %d\n", ev->type);
            pi->state = TTP_PS_ERROR;
            break;
        }
        break;
    case TTP_PS_ACCEPT_VALUE:
        switch (ev->type) {
        case YAML_SCALAR_EVENT:
            pi->value = (char*)ev->data.scalar.value;
            switch (pi->sstate) {
            case TTP_PSS_CPU:
                (void)ttp_process_cpu_event(pi, ev);
                break;
            case TTP_PSS_NET_IF_CLIENT:
            case TTP_PSS_NET_IF_SERVER:
                (void)ttp_process_net_if_event(pi, ev);
                break;
            case TTP_PSS_LOAD:
                (void)ttp_process_load_event(pi, ev);
                break;
            default:
                break;
            }
            break;
        case YAML_MAPPING_START_EVENT:
            pi->state = TTP_PS_ACCEPT_KEY;
            break;
        case YAML_DOCUMENT_END_EVENT:
            pi->state = TTP_PS_START;
            break;
        default:
            fprintf(stderr, "unexpected event while getting value: %d\n", ev->type);
            pi->state = TTP_PS_ERROR;
            break;
        }
        break;
    case TTP_PS_ERROR:
    case TTP_PS_STOP:
        break;
    }

    return (pi->state == TTP_PS_ERROR ? 0 : 1);
}

static int ttp_validate_conf(void)
{
    if (0 == s_ttp_conf.cpu.rt_client_na_num
        && s_ttp_conf.cpu.rt_client_np_num > 1
        && s_ttp_conf.net_if.client.type != LUNE_NET_IF_DPDK_QUEUE) {
        fprintf(stderr, "invalid NP number for interface %s: %d\n",
            s_ttp_conf.net_if.client.name, s_ttp_conf.cpu.rt_client_np_num);
        return -1;
    }

    if (s_ttp_conf.cpu.rt_client_na_num > 1
        && s_ttp_conf.net_if.client.type != LUNE_NET_IF_DPDK_QUEUE) {
        fprintf(stderr, "invalid NA number for interface %s: %d\n",
            s_ttp_conf.net_if.client.name, s_ttp_conf.cpu.rt_client_np_num);
        return -1;
    }

    if (0 == s_ttp_conf.cpu.rt_server_na_num
        && s_ttp_conf.cpu.rt_server_np_num > 1
        && s_ttp_conf.net_if.server.type != LUNE_NET_IF_DPDK_QUEUE) {
        fprintf(stderr, "invalid NP number for interface %s: %d\n",
            s_ttp_conf.net_if.server.name, s_ttp_conf.cpu.rt_server_np_num);
        return -1;
    }

    if (s_ttp_conf.cpu.rt_server_na_num > 1
        && s_ttp_conf.net_if.server.type != LUNE_NET_IF_DPDK_QUEUE) {
        fprintf(stderr, "invalid NA number for interface %s: %d\n",
            s_ttp_conf.net_if.server.name, s_ttp_conf.cpu.rt_server_np_num);
        return -1;
    }

    return 0;
}

int ttp_parse_conf_file(const char *ttp_conf_file)
{
    yaml_parser_t parser;
    yaml_event_t ev;
    ttp_parser_ins_t pi = {.state = TTP_PS_START, .sstate = TTP_PSS_NONE, .accepted = 0, .error = 0};
    FILE *fp;

    if (NULL == (fp = fopen(ttp_conf_file, "r"))) {
        fprintf(stderr, "failed to open config file: %s\n", ttp_conf_file);
        return -1;
    }

    memset(&s_ttp_conf, 0xff, sizeof(s_ttp_conf));
    yaml_parser_initialize(&parser);
    yaml_parser_set_input_file(&parser, fp);

    do {
        if (!yaml_parser_parse(&parser, &ev)) {
            goto ERR;
        }

        if (!ttp_process_event(&pi, &ev)) {
            goto ERR;
        }

        if (pi.accepted) {
            fprintf(stdout, "load %s complete\n", ttp_conf_file);
        }

        yaml_event_delete(&ev);
    } while (pi.state != TTP_PS_STOP);

    if (ttp_validate_conf()) {
        return -1;
    }

    s_ttp_conf.load.rate_per_core = s_ttp_conf.load.rate / s_ttp_conf.cpu.rt_client_np_num;
    if (0 == s_ttp_conf.load.rate_per_core) {
        return -1;
    }

    s_ttp_conf.load.max_cc_per_core = s_ttp_conf.load.max_cc / s_ttp_conf.cpu.rt_client_np_num;

    yaml_parser_delete(&parser);
    return 0;

ERR:
    yaml_parser_delete(&parser);
    fclose(fp);
    return -1;
}

static void ttp_client_np_stats_func(void *data)
{
    static __thread unsigned int sec = 0;
    lune_net_if_stats_t stats;
    int err;

    if (0 != (err = lune_get_net_if_opt(s_ttp_np_net_if_id,
        LUNE_NET_IF_OPT_GET_STATS, &stats, sizeof(stats)))) {
        if (-LUNE_ERR_ID_NOT_FOUND != err) {
            lune_log(LUNE_INFO, "[TTP] failed to get statistics of interface %d: %s",
                s_ttp_np_net_if_id, lune_get_err_str(err));
        }

        return;
    }

    sec++;

    if (TTP_LOAD_SSL_VER_NONE != s_ttp_local_conf.load.ssl_ver) {
        lune_net_if_ssl_stats_t ssl_stats;

        lune_assert(!lune_get_net_if_opt(s_ttp_np_net_if_id,
            LUNE_NET_IF_OPT_GET_SSL_STATS, &ssl_stats, sizeof(ssl_stats)));

        lune_log(LUNE_DBG, "[TTP] %d sec: established SSL connection rate %d "
            "total established SSL connections %d concurrent SSL connections %d Rx Bps %lld",
            sec,
            ssl_stats.est_conn_rate,
            ssl_stats.total_est_conns,
            ssl_stats.concurrent_conns,
            stats.byte_in_rate);
    } else {
        lune_net_if_tcp_stats_t tcp_stats;

        lune_assert(!lune_get_net_if_opt(s_ttp_np_net_if_id,
            LUNE_NET_IF_OPT_GET_TCP_STATS, &tcp_stats, sizeof(tcp_stats)));

        lune_log(LUNE_DBG, "[TTP] %d sec: established TCP connection rate %d "
            "total established TCP connections %d concurrent TCP connections %d Rx Bps %lld",
            sec,
            tcp_stats.est_conn_rate,
            tcp_stats.total_est_conns,
            tcp_stats.concurrent_conns,
            stats.byte_in_rate);
    }
}

static void ttp_server_np_stats_func(void *data)
{
    static __thread unsigned int sec = 0;
    lune_net_if_stats_t stats;
    lune_net_if_tcp_stats_t tcp_stats;
    int err;

    if (0 != (err = lune_get_net_if_opt(s_ttp_np_net_if_id,
        LUNE_NET_IF_OPT_GET_STATS, &stats, sizeof(stats)))) {
        if (-LUNE_ERR_ID_NOT_FOUND != err) {
            lune_log(LUNE_INFO, "[TTP] failed to get statistics of interface %d: %s",
                s_ttp_np_net_if_id, lune_get_err_str(err));
        }

        return;
    }

    lune_assert(!lune_get_net_if_opt(s_ttp_np_net_if_id,
        LUNE_NET_IF_OPT_GET_TCP_STATS, &tcp_stats, sizeof(tcp_stats)));

    sec++;

    lune_log(LUNE_DBG, "[TTP] %d sec: established connection rate %d "
        "total established connections %d concurrent connections %d Tx Bps %lld",
        sec,
        tcp_stats.est_conn_rate,
        tcp_stats.total_est_conns,
        tcp_stats.concurrent_conns,
        stats.byte_out_rate);
}

static void ttp_server_send_grat_arp_func(void *data)
{
    static __thread unsigned int sec = 1;

    if (sec < TTP_PRE_RUN_TIME_IN_SEC) {
        if (!s_ttp_local_conf.load.is_ipv6 && data) {
            /* only send on the first NP */
            (void)lune_send_grat_arp(s_ttp_np_ip_id_array[0]);
        }

        sec++;
        return;
    }

    lune_assert(!lune_reuse_timer(&s_ttp_np_tmr,
        LUNE_TIMER_RECURRING, LUNE_TIMER_RES_DEFAULT, ttp_server_np_stats_func, NULL));
    lune_assert(!lune_add_timer(&s_ttp_np_tmr, 1 * LUNE_TIME_SECOND));

    lune_log(LUNE_INFO, "server NP starting");
}

static void ttp_client_connect(void *data)
{
    ttp_socket_t *tsk = (ttp_socket_t *)data;
    int len;

    if (0 == s_ttp_local_conf.load.pkt_cnt) {
        (void)lune_set_socket_opt_in_cb(LUNE_SOCKET_OPT_SET_RST_CLOSE, NULL, 0);
        (void)lune_close_in_cb();
        return;
    }

    if (s_ttp_local_conf.load.payload_len != (len =
        lune_send_in_cb(s_ttp_payload_buf, s_ttp_local_conf.load.payload_len))) {
        lune_log(LUNE_DBG, "[TTP] failed to send tcp message with size %d on socket %d: %d",
            s_ttp_local_conf.load.payload_len, tsk->socket_id, len);
    }
}

static void ttp_client_recv(void *data, const unsigned char *buf, unsigned int len)
{
    ttp_socket_t *tsk = (ttp_socket_t *)data;

    if (unlikely(len != s_ttp_local_conf.load.payload_len)) {
        goto RST_CLOSE;
    }

    if (++tsk->pkt_cnt < s_ttp_local_conf.load.pkt_cnt) {
        return;
    }

RST_CLOSE:
    (void)lune_set_socket_opt_in_cb(LUNE_SOCKET_OPT_SET_RST_CLOSE, NULL, 0);
    (void)lune_close_in_cb();
}

static void ttp_client_error(ttp_socket_t *tsk, int err_code)
{
    lune_log(LUNE_DBG, "[TTP] client error(%d) on socket %d", err_code, tsk->socket_id);
    s_ttp_concurrent_socket_cnt--;
    lune_mem_pool_free(s_ttp_np_socket_mem_pool, tsk);
}

static void ttp_client_close(ttp_socket_t *tsk, unsigned int close_type)
{
    s_ttp_concurrent_socket_cnt--;
    lune_mem_pool_free(s_ttp_np_socket_mem_pool, tsk);
}

static void ttp_server_send(ttp_socket_t *tsk)
{
    int len;

    if (s_ttp_stop_flag) {
        lune_del_timer(&tsk->tmr);
        goto RST_CLOSE;
    }

    if (unlikely(s_ttp_local_conf.load.payload_len != (len = lune_send(tsk->socket_id,
        s_ttp_payload_buf, s_ttp_local_conf.load.payload_len)))) {
        if (len < 0) {
            lune_log(LUNE_DBG, "[TTP] failed to send %d bytes on socket %d: %s",
                s_ttp_local_conf.load.payload_len, tsk->socket_id, lune_get_err_str(len));
        } else {
            lune_log(LUNE_DBG, "[TTP] %d bytes sent on socket %d, less than expected %d bytes",
                len, tsk->socket_id, s_ttp_local_conf.load.payload_len);
        }
        lune_del_timer(&tsk->tmr);
        goto RST_CLOSE;
    }

    if (++tsk->pkt_cnt >= s_ttp_local_conf.load.pkt_cnt) {
        lune_del_timer(&tsk->tmr);
    }

    return;

RST_CLOSE:
    (void)lune_set_socket_opt(tsk->socket_id, LUNE_SOCKET_OPT_SET_RST_CLOSE, NULL, 0);
    (void)lune_close(tsk->socket_id);
}

static void ttp_server_accept(unsigned int socket_id, lune_socket_addr_t *addr, void **pdata)
{
    ttp_socket_t *tsk;

    lune_assert(NULL != pdata);

    if (unlikely(NULL == (tsk = lune_mem_pool_alloc(s_ttp_np_socket_mem_pool)))) {
        lune_log(LUNE_DBG, "[TTP] failed to allocate memory");
        (void)lune_set_socket_opt(socket_id, LUNE_SOCKET_OPT_SET_RST_CLOSE, NULL, 0);
        (void)lune_close(socket_id);
        return;
    }

    s_ttp_concurrent_socket_cnt++;

    tsk->socket_id = socket_id;
    tsk->pkt_cnt = 0;
    if (s_ttp_local_conf.load.pkt_cnt > 1) {
        lune_assert(!lune_init_timer(&tsk->tmr, LUNE_TIMER_RECURRING, LUNE_TIMER_RES_DEFAULT,
            (lune_timer_func_t)ttp_server_send, tsk));
    }
    *pdata = tsk;
}

static void ttp_server_recv(ttp_socket_t *tsk, const unsigned char *buf, unsigned int len)
{
    if (unlikely(len != s_ttp_local_conf.load.payload_len
        || tsk->pkt_cnt > 0)) {
        goto RST_CLOSE;
    }

    if (s_ttp_local_conf.load.payload_len != (len =
        lune_send_in_cb(s_ttp_payload_buf, s_ttp_local_conf.load.payload_len))) {
        lune_log(LUNE_DBG, "[TTP] failed to send tcp message with size %d on socket %d: %d",
            s_ttp_local_conf.load.payload_len, tsk->socket_id, len);
        goto RST_CLOSE;
    }

    if (s_ttp_local_conf.load.pkt_cnt > 1) {
        lune_assert(!lune_add_timer(&tsk->tmr,
            s_ttp_local_conf.load.pkt_intvl * LUNE_TIME_MILLISECOND));
    }

    return;

RST_CLOSE:
    (void)lune_set_socket_opt_in_cb(LUNE_SOCKET_OPT_SET_RST_CLOSE, NULL, 0);
    (void)lune_close_in_cb();
}

static void ttp_server_closewait(void *data)
{
    (void)lune_set_socket_opt_in_cb(LUNE_SOCKET_OPT_SET_RST_CLOSE, NULL, 0);
    (void)lune_close_in_cb();
}

static void ttp_server_error(ttp_socket_t *tsk, int err_code)
{
    if (s_ttp_local_conf.load.pkt_cnt > 1
        && LUNE_TIMER_IS_ADDED(tsk->tmr)) {
        lune_del_timer(&tsk->tmr);
    }

    lune_log(LUNE_DBG, "[TTP] server error(%d) on socket %d", err_code, tsk->socket_id);

    s_ttp_concurrent_socket_cnt--;
    lune_mem_pool_free(s_ttp_np_socket_mem_pool, tsk);
}

static void ttp_server_close(ttp_socket_t *tsk, unsigned int close_type)
{
    if (s_ttp_local_conf.load.pkt_cnt > 1
        && LUNE_TIMER_IS_ADDED(tsk->tmr)) {
        lune_del_timer(&tsk->tmr);
    }

    s_ttp_concurrent_socket_cnt--;
    lune_mem_pool_free(s_ttp_np_socket_mem_pool, tsk);
}

static __thread lune_tcp_socket_callback_t s_ttp_tcp_client_cb = {
    .connect = (lune_tcp_socket_connect_callback_func_t)ttp_client_connect,
    .accept = NULL,
    .recv = (lune_tcp_socket_recv_callback_func_t)ttp_client_recv,
    .closewait = NULL,
    .error = (lune_tcp_socket_error_callback_func_t)ttp_client_error,
    .close = (lune_tcp_socket_close_callback_func_t)ttp_client_close,
    .data = NULL,
};

static __thread lune_ssl_socket_callback_t s_ttp_ssl_client_cb = {
    .connect = (lune_ssl_socket_connect_callback_func_t)ttp_client_connect,
    .accept = NULL,
    .recv = (lune_ssl_socket_recv_callback_func_t)ttp_client_recv,
    .error = (lune_ssl_socket_error_callback_func_t)ttp_client_error,
    .close = (lune_ssl_socket_close_callback_func_t)ttp_client_close,
    .data = NULL,
};

static __thread lune_tcp_socket_callback_t s_ttp_tcp_server_cb = {
    .connect = NULL,
    .accept = (lune_tcp_socket_accept_callback_func_t)ttp_server_accept,
    .recv = (lune_tcp_socket_recv_callback_func_t)ttp_server_recv,
    .closewait = (lune_tcp_socket_closewait_callback_func_t)ttp_server_closewait,
    .error = (lune_tcp_socket_error_callback_func_t)ttp_server_error,
    .close = (lune_tcp_socket_close_callback_func_t)ttp_server_close,
    .data = NULL,
};

static __thread lune_ssl_socket_callback_t s_ttp_ssl_server_cb = {
    .connect = NULL,
    .accept = (lune_ssl_socket_accept_callback_func_t)ttp_server_accept,
    .recv = (lune_ssl_socket_recv_callback_func_t)ttp_server_recv,
    .error = (lune_ssl_socket_error_callback_func_t)ttp_server_error,
    .close = (lune_ssl_socket_close_callback_func_t)ttp_server_close,
    .data = NULL,
};

static void ttp_client_np_run(void *data)
{
    int i, cnt;
    ttp_socket_t *tsk;
    lune_socket_addr_t laddr, raddr;
    static __thread unsigned int tick = 0;

    if (s_ttp_stop_flag) {
        lune_assert(!lune_del_task(s_ttp_np_client_run_task_id));
        s_ttp_np_client_run_task_id = LUNE_INVALID_ID;
        lune_log(LUNE_INFO, "client NP stopping");
        return;
    }

    if (!s_ttp_start_flag) {
        return;
    }

    if (0 == tick) {
        s_ttp_np_client_conn_per_tick_q =
                    s_ttp_local_conf.load.rate_per_core / LUNE_TIME_GET_HZ();
        s_ttp_np_client_conn_per_tick_r =
            (float)(s_ttp_local_conf.load.rate_per_core % LUNE_TIME_GET_HZ()) / LUNE_TIME_GET_HZ();
        s_ttp_np_client_conn_accum_r = s_ttp_np_client_conn_per_tick_r;

        lune_assert(!lune_init_timer(&s_ttp_np_tmr, LUNE_TIMER_RECURRING, LUNE_TIMER_RES_DEFAULT,
            ttp_client_np_stats_func, NULL));
        lune_assert(!lune_add_timer(&s_ttp_np_tmr, 1 * LUNE_TIME_SECOND));

        lune_log(LUNE_INFO, "client NP starting");
    }

    tick++;
    if (s_ttp_np_client_conn_accum_r >= 1) {
        cnt = s_ttp_np_client_conn_per_tick_q + 1;
        s_ttp_np_client_conn_accum_r = s_ttp_np_client_conn_accum_r + s_ttp_np_client_conn_per_tick_r - 1;
    } else {
        cnt = s_ttp_np_client_conn_per_tick_q;
        s_ttp_np_client_conn_accum_r = s_ttp_np_client_conn_accum_r + s_ttp_np_client_conn_per_tick_r;
    }

    if (s_ttp_concurrent_socket_cnt >= s_ttp_local_conf.load.max_cc_per_core) {
        return;
    }
    cnt = (s_ttp_concurrent_socket_cnt + cnt) < s_ttp_local_conf.load.max_cc_per_core
        ? cnt : (s_ttp_local_conf.load.max_cc_per_core - s_ttp_concurrent_socket_cnt);

    LUNE_IP_CPY(&raddr.addr, &s_ttp_np_server_ip);
    raddr.port = TTP_SERVER_PORT;

    if (TTP_LOAD_SSL_VER_NONE != s_ttp_local_conf.load.ssl_ver) {
        for (i = 0; i < cnt; i++) {
            if (NULL == (tsk = lune_mem_pool_alloc(s_ttp_np_socket_mem_pool))) {
                lune_log(LUNE_DBG, "[TTP] failed to allocate memory");
                return;
            }

            tsk->pkt_cnt = 0;

            if (LUNE_INVALID_ID == (tsk->socket_id = lune_socket(LUNE_SOCKET_SSL))) {
                lune_log(LUNE_DBG, "[TTP] failed to create client socket: %s", lune_get_last_err_str());
                lune_mem_pool_free(s_ttp_np_socket_mem_pool, tsk);
                return;
            }

            laddr.id = s_ttp_np_ip_id_array[s_ttp_np_ip_id_offset];
            laddr.port = s_ttp_np_start_port + s_ttp_np_port_offset;
            if (0 != lune_bind(tsk->socket_id, &laddr, sizeof(laddr))) {
                lune_log(LUNE_DBG, "[TTP] failed to bind client socket %d: %s",
                    tsk->socket_id, lune_get_last_err_str());
                lune_assert(!lune_close(tsk->socket_id));
                lune_mem_pool_free(s_ttp_np_socket_mem_pool, tsk);
                continue;
            }

            s_ttp_ssl_client_cb.data = tsk;
            if (0 != lune_set_socket_opt(tsk->socket_id,
                LUNE_SOCKET_OPT_SET_CALLBACK,
                (unsigned char *)&s_ttp_ssl_client_cb,
                sizeof(s_ttp_ssl_client_cb))) {
                lune_log(LUNE_DBG, "[TTP] failed to set callback functions to "
                    "client socket %d: %s",
                    tsk->socket_id, lune_get_last_err_str());
                lune_assert(!lune_close(tsk->socket_id));
                lune_mem_pool_free(s_ttp_np_socket_mem_pool, tsk);
                s_ttp_ssl_client_cb.data = NULL;
                continue;
            }
            s_ttp_ssl_client_cb.data = NULL;

            if (0 != lune_set_socket_opt(tsk->socket_id,
                LUNE_SOCKET_OPT_SET_SSL,
                (unsigned char *)&s_ttp_np_ssl_id,
                sizeof(s_ttp_np_ssl_id))) {
                lune_log(LUNE_DBG, "[TTP] failed to set ssl to client socket %d: %s",
                    tsk->socket_id, lune_get_last_err_str());
                lune_assert(!lune_close(tsk->socket_id));
                lune_mem_pool_free(s_ttp_np_socket_mem_pool, tsk);
                continue;
            }

            if (0 != lune_connect(tsk->socket_id, (void *)&raddr, sizeof(raddr))) {
                lune_log(LUNE_DBG, "[TTP] failed to connect client socket %d: %s",
                    tsk->socket_id, lune_get_last_err_str());
                lune_assert(!lune_close(tsk->socket_id));
                lune_mem_pool_free(s_ttp_np_socket_mem_pool, tsk);
                return;
            }

            s_ttp_concurrent_socket_cnt++;

            s_ttp_np_ip_id_offset = (s_ttp_np_ip_id_offset + 1) % s_ttp_np_ip_id_cnt;
            if (0 == s_ttp_np_ip_id_offset) {
                s_ttp_np_port_offset = (s_ttp_np_port_offset + 1) % (s_ttp_np_end_port - s_ttp_np_start_port);
            }
        }
    } else {
        for (i = 0; i < cnt; i++) {
            if (NULL == (tsk = lune_mem_pool_alloc(s_ttp_np_socket_mem_pool))) {
                lune_log(LUNE_DBG, "[TTP] failed to allocate memory");
                return;
            }

            tsk->pkt_cnt = 0;

            if (LUNE_INVALID_ID == (tsk->socket_id = lune_socket(LUNE_SOCKET_TCP))) {
                lune_log(LUNE_DBG, "[TTP] failed to create client socket: %s", lune_get_last_err_str());
                lune_mem_pool_free(s_ttp_np_socket_mem_pool, tsk);
                return;
            }

            laddr.id = s_ttp_np_ip_id_array[s_ttp_np_ip_id_offset];
            laddr.port = s_ttp_np_start_port + s_ttp_np_port_offset;
            if (0 != lune_bind(tsk->socket_id, &laddr, sizeof(laddr))) {
                lune_log(LUNE_DBG, "[TTP] failed to bind client socket %d: %s",
                    tsk->socket_id, lune_get_last_err_str());
                lune_assert(!lune_close(tsk->socket_id));
                lune_mem_pool_free(s_ttp_np_socket_mem_pool, tsk);
                continue;
            }

            s_ttp_tcp_client_cb.data = tsk;
            if (0 != lune_set_socket_opt(tsk->socket_id,
                LUNE_SOCKET_OPT_SET_CALLBACK,
                (unsigned char *)&s_ttp_tcp_client_cb,
                sizeof(s_ttp_tcp_client_cb))) {
                lune_log(LUNE_DBG, "[TTP] failed to set callback functions to "
                    "client socket %d: %s",
                    tsk->socket_id, lune_get_last_err_str());
                lune_assert(!lune_close(tsk->socket_id));
                lune_mem_pool_free(s_ttp_np_socket_mem_pool, tsk);
                s_ttp_tcp_client_cb.data = NULL;
                continue;
            }
            s_ttp_tcp_client_cb.data = NULL;

            if (0 != lune_connect(tsk->socket_id, (void *)&raddr, sizeof(raddr))) {
                lune_log(LUNE_DBG, "[TTP] failed to connect client socket %d: %s",
                    tsk->socket_id, lune_get_last_err_str());
                lune_assert(!lune_close(tsk->socket_id));
                lune_mem_pool_free(s_ttp_np_socket_mem_pool, tsk);
                return;
            }

            s_ttp_concurrent_socket_cnt++;

            s_ttp_np_ip_id_offset = (s_ttp_np_ip_id_offset + 1) % s_ttp_np_ip_id_cnt;
            if (0 == s_ttp_np_ip_id_offset) {
                s_ttp_np_port_offset = (s_ttp_np_port_offset + 1) % (s_ttp_np_end_port - s_ttp_np_start_port);
            }
        }
    }
}

static void ttp_client_np_init(void *data)
{
    int i, err;
    unsigned long long start_mac_ll;
    lune_mac_addr_t client_mac;
    unsigned int step, chan_id, na_id = (unsigned int)(unsigned long long)data;

    if (!s_ttp_client_net_if_enable_flag) {
        /* interface not added or not enabled yet */
        return;
    }

    memcpy(&s_ttp_local_conf, &s_ttp_conf, sizeof(s_ttp_conf));

    if (0 != (err = lune_get_net_if_opt(s_ttp_np_net_if_id,
        LUNE_NET_IF_OPT_GET_CHAN_ID, (void *)&chan_id, sizeof(chan_id)))) {
        if (-LUNE_ERR_NOT_SUPPORTED == err) {
            chan_id = 0;
        } else {
            lune_log(LUNE_INFO, "[TTP] failed to get channel id of interface %d: %s",
                s_ttp_np_net_if_id, lune_get_err_str(err));
            goto ERR_1;
        }
    }

    if (NULL == (s_ttp_np_socket_mem_pool =
        lune_create_mem_pool("ttp client NP socket", sizeof(ttp_socket_t)))) {
        lune_log(LUNE_INFO, "[TTP] failed to create memory pool of socket: %s",
            lune_get_err_str(lune_get_err_no()));
        goto ERR_1;
    }

    if (TTP_LOAD_SSL_VER_NONE != s_ttp_local_conf.load.ssl_ver) {
#ifdef LUNE_BUILD_SSL
        if (LUNE_INVALID_ID == (s_ttp_np_ssl_id = ttp_ssl_create_client_ssl(
            TTP_LOAD_SSL_VER_TLS_1_2 == s_ttp_local_conf.load.ssl_ver
            ? LUNE_SSL_VERSION_TLSV1_2 : LUNE_SSL_VERSION_TLSV1_3))) {
            goto ERR_2;
        }
#else
        s_ttp_np_ssl_id = LUNE_INVALID_ID;
        goto ERR_2;
#endif
    } else {
        s_ttp_np_ssl_id = LUNE_INVALID_ID;
    }

    s_ttp_np_start_port = TTP_CLIENT_START_PORT;
    s_ttp_np_end_port = TTP_CLIENT_END_PORT;
    s_ttp_np_port_offset = 0;
    s_ttp_np_ip_id_offset = 0;

    lune_assert(!lune_str_to_mac(TTP_CLIENT_START_MAC, client_mac));
    LUNE_MAC_TO_LL(client_mac, start_mac_ll);
    start_mac_ll = start_mac_ll + na_id + chan_id * s_ttp_local_conf.cpu.rt_client_na_num;

    step = s_ttp_local_conf.cpu.rt_client_np_num;

    if (s_ttp_local_conf.load.is_ipv6) {
        lune_ipv6_addr_t start_ipv6, end_ipv6;

        lune_assert(!lune_str_to_ipv6(TTP_CLIENT_START_IPV6, &start_ipv6));
        start_ipv6.addr[3] = lune_htonl(lune_ntohl(start_ipv6.addr[3])
            + na_id + chan_id * s_ttp_local_conf.cpu.rt_client_na_num);
        lune_assert(!lune_str_to_ipv6(TTP_CLIENT_END_IPV6, &end_ipv6));
        s_ttp_np_ip_id_cnt =
            (lune_ntohl(end_ipv6.addr[3]) - lune_ntohl(start_ipv6.addr[3])) / step + 1;
        s_ttp_np_server_ip.is_ipv6 = 1;
        lune_assert(!lune_str_to_ipv6(TTP_SERVER_IPV6, &s_ttp_np_server_ip.ipv6));
        for (i = 0; i < s_ttp_np_ip_id_cnt; i++) {
            lune_mac_addr_t mac;
            LUNE_LL_TO_MAC(start_mac_ll + i * step, mac);
            lune_assert(LUNE_INVALID_ID != (s_ttp_np_mac_id_array[i] = lune_add_mac(mac,
                LUNE_ID_NET_IF, s_ttp_np_net_if_id)));
            lune_assert(!lune_enable_mac(s_ttp_np_mac_id_array[i]));
            start_ipv6.addr[3] = lune_htonl(lune_ntohl(start_ipv6.addr[3]) + step);
            lune_assert(LUNE_INVALID_ID != (s_ttp_np_ip_id_array[i] =
                lune_add_ipv6(&start_ipv6, LUNE_ID_MAC, s_ttp_np_mac_id_array[i])));
        }
    } else {
        lune_ipv4_addr_t mask, gw, start_ipv4, end_ipv4;

        lune_assert(!lune_str_to_ipv4(TTP_CLIENT_START_IPV4, &start_ipv4));
        start_ipv4 = start_ipv4 + na_id + chan_id * s_ttp_local_conf.cpu.rt_client_na_num;
        lune_assert(!lune_str_to_ipv4(TTP_CLIENT_END_IPV4, &end_ipv4));
        lune_assert(!lune_str_to_ipv4(TTP_CLIENT_MASK, &mask));
        lune_assert(!lune_str_to_ipv4(TTP_CLIENT_GW, &gw));
        s_ttp_np_ip_id_cnt = (end_ipv4 - start_ipv4) / step + 1;
        s_ttp_np_server_ip.is_ipv6 = 0;
        lune_assert(!lune_str_to_ipv4(TTP_SERVER_IPV4, &s_ttp_np_server_ip.ipv4));
        for (i = 0; i < s_ttp_np_ip_id_cnt; i++) {
            lune_mac_addr_t mac;
            LUNE_LL_TO_MAC(start_mac_ll + i * step, mac);
            lune_assert(LUNE_INVALID_ID != (s_ttp_np_mac_id_array[i] = lune_add_mac(mac,
                LUNE_ID_NET_IF, s_ttp_np_net_if_id)));
            lune_assert(!lune_enable_mac(s_ttp_np_mac_id_array[i]));
            lune_assert(LUNE_INVALID_ID != (s_ttp_np_ip_id_array[i] =
                lune_add_ipv4(start_ipv4 + i * step,
                    mask, gw, LUNE_ID_MAC, s_ttp_np_mac_id_array[i])));
        }
    }

    s_ttp_concurrent_socket_cnt = 0;

    lune_assert(LUNE_INVALID_ID != (s_ttp_np_client_run_task_id =
        lune_add_task("ttp client NP run", ttp_client_np_run, NULL, LUNE_TASK_PRIO_HIGH)));

    lune_assert(!lune_del_task(s_ttp_np_init_task_id));
    s_ttp_np_init_task_id = LUNE_INVALID_ID;
    return;

ERR_2:
    lune_delete_mem_pool(s_ttp_np_socket_mem_pool);

ERR_1:
    lune_assert(!lune_del_task(s_ttp_np_init_task_id));
    s_ttp_np_init_task_id = LUNE_INVALID_ID;
}

static int __ttp_client_np_init(void *data)
{
    s_ttp_np_net_if_id = s_ttp_client_net_if_id;

    if (LUNE_INVALID_ID == (s_ttp_np_init_task_id =
        lune_add_task("ttp client NP init", ttp_client_np_init, data, LUNE_TASK_PRIO_HIGH))) {
        return lune_get_err_no();
    }

    return 0;
}

static void __ttp_client_np_fini(void)
{
    int i;

    lune_assert(0 == s_ttp_np_net_if_id);
    lune_assert(LUNE_INVALID_ID == s_ttp_np_init_task_id);

    lune_assert(!lune_del_timer(&s_ttp_np_tmr));

    if (LUNE_INVALID_ID != s_ttp_np_client_run_task_id) {
        lune_assert(!lune_del_task(s_ttp_np_client_run_task_id));
        s_ttp_np_client_run_task_id = LUNE_INVALID_ID;
    }

    for (i = 0; i < s_ttp_np_ip_id_cnt; i++) {
        if (s_ttp_local_conf.load.is_ipv6) {
            lune_assert(!lune_del_ipv6(s_ttp_np_ip_id_array[i]));
        } else {
            lune_assert(!lune_del_ipv4(s_ttp_np_ip_id_array[i]));
        }
        lune_assert(!lune_del_mac(s_ttp_np_mac_id_array[i]));
    }

#ifdef LUNE_BUILD_SSL
    if (LUNE_INVALID_ID != s_ttp_np_ssl_id) {
        lune_assert(!ttp_ssl_delete_client_ssl(s_ttp_np_ssl_id));
    }
#endif

    lune_delete_mem_pool(s_ttp_np_socket_mem_pool);
}

static void ttp_server_np_init(void *data)
{
    lune_socket_addr_t addr;
    lune_mac_addr_t server_mac;

    if (!s_ttp_server_net_if_enable_flag) {
        /* interface not added or not enabled yet */
        return;
    }

    memcpy(&s_ttp_local_conf, &s_ttp_conf, sizeof(s_ttp_conf));

    if (NULL == (s_ttp_np_socket_mem_pool =
        lune_create_mem_pool("ttp server NP socket", sizeof(ttp_socket_t)))) {
        lune_log(LUNE_INFO, "[TTP] failed to create memory pool of socket: %s",
            lune_get_err_str(lune_get_err_no()));
        goto ERR_1;
    }

    if (TTP_LOAD_SSL_VER_NONE != s_ttp_local_conf.load.ssl_ver) {
#ifdef LUNE_BUILD_SSL
        if (LUNE_INVALID_ID == (s_ttp_np_ssl_id = ttp_ssl_create_server_ssl(
            TTP_LOAD_SSL_VER_TLS_1_2 == s_ttp_local_conf.load.ssl_ver
            ? LUNE_SSL_VERSION_TLSV1_2 : LUNE_SSL_VERSION_TLSV1_3))) {
            goto ERR_2;
        }
#else
        s_ttp_np_ssl_id = LUNE_INVALID_ID;
        goto ERR_2;
#endif
    } else {
        s_ttp_np_ssl_id = LUNE_INVALID_ID;
    }

    lune_assert(!lune_str_to_mac(TTP_SERVER_MAC, server_mac));
    lune_assert(LUNE_INVALID_ID != (s_ttp_np_mac_id_array[0] = lune_add_mac(server_mac,
        LUNE_ID_NET_IF, s_ttp_np_net_if_id)));
    lune_assert(!lune_enable_mac(s_ttp_np_mac_id_array[0]));
    if (s_ttp_local_conf.load.is_ipv6) {
        lune_ipv6_addr_t server_ipv6;
        lune_assert(!lune_str_to_ipv6(TTP_SERVER_IPV6, &server_ipv6));
        lune_assert(LUNE_INVALID_ID != (s_ttp_np_ip_id_array[0] = lune_add_ipv6(&server_ipv6,
            LUNE_ID_MAC, s_ttp_np_mac_id_array[0])));
    } else {
        lune_ipv4_addr_t server_ipv4, mask = 0, gw = 0;
        lune_assert(!lune_str_to_ipv4(TTP_SERVER_IPV4, &server_ipv4));
        lune_assert(LUNE_INVALID_ID != (s_ttp_np_ip_id_array[0] = lune_add_ipv4(server_ipv4,
            mask, gw, LUNE_ID_MAC, s_ttp_np_mac_id_array[0])));
    }

    if (TTP_LOAD_SSL_VER_NONE != s_ttp_local_conf.load.ssl_ver) {
        lune_assert(LUNE_INVALID_ID != (s_ttp_np_server_socket_id =
            lune_socket(LUNE_SOCKET_SSL_LISTEN)));

        addr.id = s_ttp_np_ip_id_array[0];
        addr.port = TTP_SERVER_PORT;
        lune_assert(!lune_bind(s_ttp_np_server_socket_id, &addr, sizeof(addr)));

        lune_assert(!lune_set_socket_opt(s_ttp_np_server_socket_id,
            LUNE_SOCKET_OPT_SET_CALLBACK,
            (unsigned char *)&s_ttp_ssl_server_cb,
            sizeof(s_ttp_ssl_server_cb)));

        lune_assert(!lune_set_socket_opt(s_ttp_np_server_socket_id,
            LUNE_SOCKET_OPT_SET_SSL,
            (unsigned char *)&s_ttp_np_ssl_id,
            sizeof(s_ttp_np_ssl_id)));
    } else {
        lune_assert(LUNE_INVALID_ID != (s_ttp_np_server_socket_id =
            lune_socket(LUNE_SOCKET_TCP_LISTEN)));

        addr.id = s_ttp_np_ip_id_array[0];
        addr.port = TTP_SERVER_PORT;
        lune_assert(!lune_bind(s_ttp_np_server_socket_id, &addr, sizeof(addr)));

        lune_assert(!lune_set_socket_opt(s_ttp_np_server_socket_id,
            LUNE_SOCKET_OPT_SET_CALLBACK,
            (unsigned char *)&s_ttp_tcp_server_cb,
            sizeof(s_ttp_tcp_server_cb)));
    }

    lune_assert(!lune_listen(s_ttp_np_server_socket_id, LUNE_TCP_LISTEN_BACKLOG_UNLIMITED));

    lune_assert(!lune_init_timer(&s_ttp_np_tmr,
        LUNE_TIMER_RECURRING, LUNE_TIMER_RES_DEFAULT, ttp_server_send_grat_arp_func, data));
    lune_assert(!lune_add_timer(&s_ttp_np_tmr, 1 * LUNE_TIME_SECOND));

    lune_assert(!lune_del_task(s_ttp_np_init_task_id));
    s_ttp_np_init_task_id = LUNE_INVALID_ID;
    return;

ERR_2:
    lune_delete_mem_pool(s_ttp_np_socket_mem_pool);

ERR_1:
    lune_assert(!lune_del_task(s_ttp_np_init_task_id));
    s_ttp_np_init_task_id = LUNE_INVALID_ID;
}

static int __ttp_server_np_init(void *data)
{
    s_ttp_np_net_if_id = s_ttp_server_net_if_id;

    if (LUNE_INVALID_ID == (s_ttp_np_init_task_id =
        lune_add_task("ttp server NP init", ttp_server_np_init, data, LUNE_TASK_PRIO_HIGH))) {
        return lune_get_err_no();
    }

    return 0;
}

static void __ttp_server_np_fini(void)
{
    lune_assert(0 == s_ttp_np_net_if_id);
    lune_assert(LUNE_INVALID_ID == s_ttp_np_init_task_id);

    lune_assert(!lune_del_timer(&s_ttp_np_tmr));

    lune_assert(!lune_close(s_ttp_np_server_socket_id));
    if (s_ttp_local_conf.load.is_ipv6) {
        lune_assert(!lune_del_ipv6(s_ttp_np_ip_id_array[0]));
    } else {
        lune_assert(!lune_del_ipv4(s_ttp_np_ip_id_array[0]));
    }
    lune_assert(!lune_del_mac(s_ttp_np_mac_id_array[0]));

#ifdef LUNE_BUILD_SSL
    if (LUNE_INVALID_ID != s_ttp_np_ssl_id) {
        lune_assert(!ttp_ssl_delete_server_ssl(s_ttp_np_ssl_id));
    }
#endif

    lune_delete_mem_pool(s_ttp_np_socket_mem_pool);
}

static int ttp_create_np(unsigned int core_id, unsigned int is_client,
    unsigned int *cp_id_array, unsigned int cp_id_num, unsigned int na_id)
{
    lune_core_conf_t conf;
    int id, err;
    unsigned int sleep_usecs = 500, i;
    static lune_atomic32_t server_hit = {0};

    conf.id = core_id;
    conf.type = LUNE_CORE_NP;
    conf.hz = 0;
    conf.log_level = LUNE_DBG;
    sprintf(conf.log_file, "./ttp_np_%d.log", core_id);
    if (is_client) {
        conf.task.init = __ttp_client_np_init;
        conf.task.fini = __ttp_client_np_fini;
        conf.task.data = (void *)(unsigned long long)na_id;
    } else {
        conf.task.init = __ttp_server_np_init;
        conf.task.fini = __ttp_server_np_fini;
        if (1 == lune_atomic32_inc_and_return(&server_hit)) {
            /* first server NP */
            conf.task.data = (void *)1;
        } else {
            /* first server NP already created */
            conf.task.data = NULL;
        }
    }
    sprintf(conf.task.name, "NP %d", core_id);

    if (0 > (id = lune_create_core(&conf))) {
        fprintf(stderr, "failed to create NP core: %d\n", id);
        return lune_get_err_no();
    }

    while (0 == (err = lune_is_core_running(id))) {
        /* starting... */
        usleep(sleep_usecs);
    }

    if (err < 0) {
        fprintf(stderr, "failed to run NP core: %d\n", err);
        return lune_set_err_no(err);
    }

    for (i = 0; i < cp_id_num; i++) {
        if (0 != lune_set_core_opt(core_id, LUNE_CORE_OPT_BIND_CP,
            (const unsigned char *)&cp_id_array[i], sizeof(cp_id_array[i]))) {
            return lune_get_err_no();
        }
    }

    /* suppress cpu usage log occurring on regular basis */
    if (0 != lune_set_core_opt(core_id,
        LUNE_CORE_OPT_SET_LOG_CPU_USAGE_OFF, NULL, 0)) {
        return lune_get_err_no();
    }

    return id;
}

static int ttp_delete_np(unsigned int id)
{
    return lune_delete_core(id);
}

static int ttp_create_na(unsigned int core_id)
{
    lune_core_conf_t conf;
    int id, err;
    unsigned int sleep_usecs = 500;

    conf.id = core_id;
    conf.type = LUNE_CORE_NA;
    conf.hz = 0;
    conf.log_level = LUNE_DBG;
    sprintf(conf.log_file, "./ttp_na_%d.log", core_id);
    conf.task.init = NULL;
    conf.task.fini = NULL;
    conf.task.data = NULL;
    sprintf(conf.task.name, "NA %d", core_id);

    if (0 > (id = lune_create_core(&conf))) {
        fprintf(stderr, "failed to create NA core: %d\n", id);
        return lune_get_err_no();
    }

    while (0 == (err = lune_is_core_running(id))) {
        /* starting... */
        usleep(sleep_usecs);
    }

    if (err < 0) {
        fprintf(stderr, "failed to run NA core: %d\n", err);
        return lune_set_err_no(err);
    }

    return id;
}

static int ttp_delete_na(unsigned int id)
{
    return lune_delete_core(id);
}

static int ttp_create_cp(unsigned int core_id, unsigned int is_client, void *data)
{
    lune_core_conf_t conf;
    int id, err;
    unsigned int sleep_usecs = 500;

    conf.id = core_id;
    conf.type = LUNE_CORE_CP;
    conf.hz = 0;
    conf.log_level = LUNE_DBG;
    sprintf(conf.log_file, "./ttp_cp_%d.log", core_id);
    conf.task.init = NULL;
    conf.task.fini = NULL;
    conf.task.data = NULL;
    sprintf(conf.task.name, "CP %d", core_id);

    if (0 > (id = lune_create_core(&conf))) {
        fprintf(stderr, "failed to create CP core: %d\n", id);
        return lune_get_err_no();
    }

    while (0 == (err = lune_is_core_running(id))) {
        /* starting... */
        usleep(sleep_usecs);
    }

    if (err < 0) {
        fprintf(stderr, "failed to run CP core: %d\n", err);
        return lune_set_err_no(err);
    }

    return id;
}

static int ttp_delete_cp(unsigned int id)
{
    return lune_delete_core(id);
}

static void ttp_create_server_cp(void)
{
    int i;

    for (i = 0; i < s_ttp_conf.cpu.rt_server_cp_num; i++) {
        if (0 > (s_ttp_server_cp_id[i] =
            ttp_create_cp(s_ttp_conf.cpu.rt_server_start + i, 0, NULL))) {
            fprintf(stderr, "failed to create server CP on core %d: %s\n",
                s_ttp_conf.cpu.rt_server_start + i,
                lune_get_err_str(s_ttp_server_cp_id[i]));
            exit(EXIT_FAILURE);
        }
    }
}

static void ttp_delete_server_cp(void)
{
    int i, err;

    for (i = 0; i < s_ttp_conf.cpu.rt_server_cp_num; i++) {
        if (0 != (err = ttp_delete_cp((unsigned int)s_ttp_server_cp_id[i]))) {
            fprintf(stderr, "failed to delete server CP on core %d: %s\n",
                s_ttp_conf.cpu.rt_server_start + i,
                lune_get_err_str(err));
            exit(EXIT_FAILURE);
        }
    }
}

static void ttp_create_client_cp(void)
{
    int i;

    for (i = 0; i < s_ttp_conf.cpu.rt_client_cp_num; i++) {
        if (0 > (s_ttp_client_cp_id[i] =
            ttp_create_cp(s_ttp_conf.cpu.rt_client_start + i, 0, NULL))) {
            fprintf(stderr, "failed to create client CP on core %d: %s\n",
                s_ttp_conf.cpu.rt_client_start + i,
                lune_get_err_str(s_ttp_client_cp_id[i]));
            exit(EXIT_FAILURE);
        }
    }
}

static void ttp_delete_client_cp(void)
{
    int i, err;

    for (i = 0; i < s_ttp_conf.cpu.rt_client_cp_num; i++) {
        if (0 != (err = ttp_delete_cp((unsigned int)s_ttp_client_cp_id[i]))) {
            fprintf(stderr, "failed to delete client CP on core %d: %s\n",
                s_ttp_conf.cpu.rt_client_start + i,
                lune_get_err_str(err));
            exit(EXIT_FAILURE);
        }
    }
}

static void ttp_create_server_np_net_if(void)
{
    unsigned int i, cp_avail, core_id;
    lune_net_if_nrt_conf_t conf;
    char cpu_list[TTP_CPU_LIST_MAX_BUF_LEN];

    cp_avail = s_ttp_conf.cpu.rt_server_cp_num;

    for (i = 0; i < s_ttp_conf.cpu.rt_server_np_num; i++) {
        core_id = s_ttp_conf.cpu.rt_server_start + cp_avail + i;
        if (0 > (s_ttp_server_np_id[i] =
            ttp_create_np(core_id, 0, (unsigned int *)s_ttp_server_cp_id, cp_avail, i))) {
            fprintf(stderr, "failed to create server NP %d for %s: %s\n",
                core_id,
                s_ttp_conf.net_if.server.name,
                lune_get_err_str(s_ttp_server_np_id[i]));
            exit(EXIT_FAILURE);
        }
    }
    sprintf(cpu_list, "%d-%d", s_ttp_conf.cpu.rt_server_start + cp_avail,
        s_ttp_conf.cpu.rt_server_start + cp_avail + s_ttp_conf.cpu.rt_server_np_num - 1);

    if (LUNE_NET_IF_DPDK == s_ttp_conf.net_if.server.type) {
        conf.dpdk_conf.txq_num = s_ttp_conf.cpu.rt_server_np_num;
    } else if (LUNE_NET_IF_DPDK_QUEUE == s_ttp_conf.net_if.server.type) {
        conf.dpdk_queue_conf.rxq_num =
            conf.dpdk_queue_conf.txq_num = s_ttp_conf.cpu.rt_server_np_num;
        conf.dpdk_queue_conf.rss_type = LUNE_NET_IF_DPDK_RSS_TYPE_L3_SRC;
    }
    conf.cpu_list = cpu_list;
    if (LUNE_INVALID_ID == (s_ttp_server_net_if_id
        = lune_add_net_if(s_ttp_conf.net_if.server.type,
            s_ttp_conf.net_if.server.name, &conf, sizeof(conf)))) {
        fprintf(stderr, "failed to add interface %s: %s\n",
            s_ttp_conf.net_if.server.name, lune_get_last_err_str());
        exit(EXIT_FAILURE);
    }
}

static void ttp_enable_server_net_if(void)
{
    int err;

    if (0 != (err = lune_enable_net_if(s_ttp_server_net_if_id))) {
        fprintf(stderr, "failed to enable interface %s: %s\n",
            s_ttp_conf.net_if.server.name, lune_get_err_str(err));
        exit(EXIT_FAILURE);
    }

    s_ttp_server_net_if_enable_flag = 1;

    if (s_ttp_conf.net_if.server.cap_enable) {
        char cap_file[LUNE_MAX_NAME_BUF_LEN];
        lune_net_if_pcap_t pcap;

        sprintf(cap_file, "./ttp_%s.pcap", s_ttp_conf.net_if.server.name);
        lune_str_replace_char(cap_file, ':', '_');

        pcap.file_name = cap_file;
        if (0 != lune_set_net_if_opt(s_ttp_server_net_if_id,
            LUNE_NET_IF_OPT_PCAP_START, &pcap, sizeof(pcap))) {
            fprintf(stderr, "failed to capture packet on interface %s\n",
                s_ttp_conf.net_if.server.name);
        }
    }
}

static void ttp_disable_server_net_if(void)
{
    int err;

    if (0 != (err = lune_disable_net_if(s_ttp_server_net_if_id))) {
        fprintf(stderr, "failed to disable interface %s: %s\n",
            s_ttp_conf.net_if.server.name, lune_get_err_str(err));
        exit(EXIT_FAILURE);
    }
}

static void ttp_delete_server_np_net_if(void)
{
    int i, err;

    if (0 != (err = lune_del_net_if(s_ttp_server_net_if_id))) {
        fprintf(stderr, "failed to delete interface %d: %s\n",
            s_ttp_server_net_if_id, lune_get_err_str(err));
        exit(EXIT_FAILURE);
    }

    for (i = 0; i < s_ttp_conf.cpu.rt_server_np_num; i++) {
        if (0 != (err = ttp_delete_np((unsigned int)s_ttp_server_np_id[i]))) {
            fprintf(stderr, "failed to delete NP %d: %s\n",
                (unsigned int)s_ttp_server_np_id[i], lune_get_err_str(err));
            exit(EXIT_FAILURE);
        }
    }
}

static void ttp_create_client_np_net_if(void)
{
    unsigned int i, cp_avail, core_id;
    lune_net_if_nrt_conf_t conf;
    char cpu_list[TTP_CPU_LIST_MAX_BUF_LEN];

    cp_avail = s_ttp_conf.cpu.rt_client_cp_num;

    for (i = 0; i < s_ttp_conf.cpu.rt_client_np_num; i++) {
        core_id = s_ttp_conf.cpu.rt_client_start + cp_avail + i;
        if (0 > (s_ttp_client_np_id[i] =
            ttp_create_np(core_id, 1, (unsigned int *)s_ttp_client_cp_id, cp_avail, i))) {
            fprintf(stderr, "failed to create client NP %d for %s: %s\n",
                core_id,
                s_ttp_conf.net_if.client.name,
                lune_get_err_str(s_ttp_client_np_id[i]));
            exit(EXIT_FAILURE);
        }
    }
    sprintf(cpu_list, "%d-%d", s_ttp_conf.cpu.rt_client_start + cp_avail,
        s_ttp_conf.cpu.rt_client_start + cp_avail + s_ttp_conf.cpu.rt_client_np_num - 1);

    if (LUNE_NET_IF_DPDK == s_ttp_conf.net_if.client.type) {
        conf.dpdk_conf.txq_num = s_ttp_conf.cpu.rt_client_np_num;
    } else if (LUNE_NET_IF_DPDK_QUEUE == s_ttp_conf.net_if.client.type) {
        conf.dpdk_queue_conf.rxq_num =
            conf.dpdk_queue_conf.txq_num = s_ttp_conf.cpu.rt_client_np_num;
        conf.dpdk_queue_conf.rss_type = LUNE_NET_IF_DPDK_RSS_TYPE_L3_DST;
    }
    conf.cpu_list = cpu_list;
    if (LUNE_INVALID_ID == (s_ttp_client_net_if_id = lune_add_net_if(s_ttp_conf.net_if.client.type,
            s_ttp_conf.net_if.client.name, &conf, sizeof(conf)))) {
        fprintf(stderr, "failed to add interface %s: %s\n",
            s_ttp_conf.net_if.client.name, lune_get_last_err_str());
        exit(EXIT_FAILURE);
    }
}

static void ttp_enable_client_net_if(void)
{
    int err;

    if (0 != (err = lune_enable_net_if(s_ttp_client_net_if_id))) {
        fprintf(stderr, "failed to enable interface %s: %s\n",
            s_ttp_conf.net_if.client.name, lune_get_err_str(err));
        exit(EXIT_FAILURE);
    }

    s_ttp_client_net_if_enable_flag = 1;

    if (s_ttp_conf.net_if.client.cap_enable) {
        char cap_file[LUNE_MAX_NAME_BUF_LEN];
        lune_net_if_pcap_t pcap;

        sprintf(cap_file, "./ttp_%s.pcap", s_ttp_conf.net_if.client.name);
        lune_str_replace_char(cap_file, ':', '_');

        pcap.file_name = cap_file;
        if (0 != lune_set_net_if_opt(s_ttp_client_net_if_id,
            LUNE_NET_IF_OPT_PCAP_START, &pcap, sizeof(pcap))) {
            fprintf(stderr, "failed to capture packet on interface %s\n",
                s_ttp_conf.net_if.client.name);
        }
    }
}

static void ttp_disable_client_net_if(void)
{
    int err;

    if (0 != (err = lune_disable_net_if(s_ttp_client_net_if_id))) {
        fprintf(stderr, "failed to disable interface %s: %s\n",
            s_ttp_conf.net_if.client.name, lune_get_err_str(err));
        exit(EXIT_FAILURE);
    }
}

static void ttp_delete_client_np_net_if(void)
{
    int i, err;

    if (0 != (err = lune_del_net_if(s_ttp_client_net_if_id))) {
        fprintf(stderr, "failed to delete interface %d: %s\n",
            s_ttp_client_net_if_id, lune_get_err_str(err));
        exit(EXIT_FAILURE);
    }

    for (i = 0; i < s_ttp_conf.cpu.rt_client_np_num; i++) {
        if (0 != (err = ttp_delete_np((unsigned int)s_ttp_client_np_id[i]))) {
            fprintf(stderr, "failed to delete NP %d: %s\n",
                (unsigned int)s_ttp_client_np_id[i], lune_get_err_str(err));
            exit(EXIT_FAILURE);
        }
    }
}

static void ttp_connect_net_if(void)
{
    int err;

    if ((LUNE_NET_IF_VIRT == s_ttp_conf.net_if.client.type
        && LUNE_NET_IF_VIRT != s_ttp_conf.net_if.server.type)
        || (LUNE_NET_IF_VIRT != s_ttp_conf.net_if.client.type
        && LUNE_NET_IF_VIRT == s_ttp_conf.net_if.server.type)) {
        fprintf(stderr, "failed to connect interface %s and %s: %s\n",
            s_ttp_conf.net_if.client.name,
            s_ttp_conf.net_if.server.name,
            lune_get_err_str(lune_set_err_no(LUNE_ERR_NET_IF_TYPE_ERR)));
        exit(EXIT_FAILURE);
    }

    if (LUNE_NET_IF_VIRT == s_ttp_conf.net_if.client.type) {
        if (0 != (err = lune_connect_net_if(s_ttp_client_net_if_id, s_ttp_server_net_if_id))) {
        fprintf(stderr, "failed to connect interface %s and %s: %s\n",
            s_ttp_conf.net_if.client.name,
            s_ttp_conf.net_if.server.name,
            lune_get_err_str(err));
            exit(EXIT_FAILURE);
        }
    }
}

static void ttp_disconnect_net_if(void)
{
    int err;

    if (LUNE_NET_IF_VIRT == s_ttp_conf.net_if.client.type) {
        if (0 != (err = lune_disconnect_net_if(s_ttp_client_net_if_id))) {
        fprintf(stderr, "failed to disconnect interface %s and %s: %s\n",
            s_ttp_conf.net_if.client.name,
            s_ttp_conf.net_if.server.name,
            lune_get_err_str(err));
            exit(EXIT_FAILURE);
        }
    }
}

static void ttp_create_server_na_np_net_if(void)
{
    int i, j;
    unsigned int server_np_num_per_na;
    unsigned int cp_avail, core_id;
    char cpu_list[TTP_CPU_LIST_MAX_BUF_LEN];
    lune_net_if_nrt_conf_t conf;
    lune_mac_addr_t start_mac;
    unsigned long long start_mac_ll;

    lune_assert(!lune_str_to_mac(TTP_CLIENT_START_MAC, start_mac));
    LUNE_MAC_TO_LL(start_mac, start_mac_ll);

    cp_avail = s_ttp_conf.cpu.rt_server_cp_num;
    server_np_num_per_na =
        s_ttp_conf.cpu.rt_server_np_num / s_ttp_conf.cpu.rt_server_na_num;
    for (i = 0; i < s_ttp_conf.cpu.rt_server_na_num; i++) {
        core_id = s_ttp_conf.cpu.rt_server_start + cp_avail + i;
        if (0 > (s_ttp_server_na_id[i] = ttp_create_na(core_id))) {
            fprintf(stderr, "failed to create server NA on core %d\n", core_id);
            exit(EXIT_FAILURE);
        }

        for (j = 0; j < server_np_num_per_na; j++) {
            core_id = s_ttp_conf.cpu.rt_server_start + cp_avail + s_ttp_conf.cpu.rt_server_na_num
                + server_np_num_per_na * i + j;
            if (0 > (s_ttp_server_np_id[server_np_num_per_na * i + j] =
                ttp_create_np(core_id, 0, (unsigned int *)s_ttp_server_cp_id, cp_avail, i))) {
                fprintf(stderr, "failed to create server NP on core %d: %s\n",
                    core_id, lune_get_err_str(s_ttp_server_np_id[server_np_num_per_na * i + j]));
                exit(EXIT_FAILURE);
            }
        }
    }
    sprintf(cpu_list, "%d-%d", s_ttp_conf.cpu.rt_server_start + cp_avail,
        s_ttp_conf.cpu.rt_server_start + cp_avail + s_ttp_conf.cpu.rt_server_na_num
        + s_ttp_conf.cpu.rt_server_np_num - 1);

    if (LUNE_NET_IF_DPDK == s_ttp_conf.net_if.server.type) {
        lune_assert(1 == s_ttp_conf.cpu.rt_server_na_num);
        conf.dpdk_conf.txq_num = s_ttp_conf.cpu.rt_server_np_num;
        conf.aggr_conf.chan_type = LUNE_NET_IF_DPDK_CHAN;
    } else if (LUNE_NET_IF_DPDK_QUEUE == s_ttp_conf.net_if.server.type) {
        lune_assert(1 != s_ttp_conf.cpu.rt_server_na_num);
        conf.dpdk_queue_conf.rxq_num = s_ttp_conf.cpu.rt_server_na_num;
        conf.dpdk_queue_conf.txq_num = s_ttp_conf.cpu.rt_server_np_num;
        conf.dpdk_queue_conf.rss_type = LUNE_NET_IF_DPDK_RSS_TYPE_L3_SRC;
        conf.aggr_conf.chan_type = LUNE_NET_IF_DPDK_QUEUE_CHAN;
    } else {
        conf.aggr_conf.chan_type = LUNE_NET_IF_CHAN;
    }
    conf.aggr_conf.conf.chan_num = s_ttp_conf.cpu.rt_server_np_num;
    conf.aggr_conf.conf.type = LUNE_NET_IF_AGGR_MAC_SERVER;
    LUNE_LL_TO_MAC(start_mac_ll, conf.aggr_conf.conf.mac.start_mac);
    lune_assert(!(lune_str_to_mac(TTP_CLIENT_END_MAC, conf.aggr_conf.conf.mac.end_mac)));
    conf.aggr_conf.conf.mac.step = 1;
    conf.cpu_list = cpu_list;
    if (LUNE_INVALID_ID == (s_ttp_server_net_if_id = lune_add_net_if(s_ttp_conf.net_if.server.type,
            s_ttp_conf.net_if.server.name, &conf, sizeof(conf)))) {
        fprintf(stderr, "failed to add interface %s: %s\n",
            s_ttp_conf.net_if.server.name, lune_get_last_err_str());
        exit(EXIT_FAILURE);
    }
}

static void ttp_delete_server_na_np_net_if(void)
{
    int i, j, err;
    unsigned int server_np_num_per_na;

    if (0 != (err = lune_del_net_if(s_ttp_server_net_if_id))) {
        fprintf(stderr, "failed to delete interface %s: %s\n",
            s_ttp_conf.net_if.server.name, lune_get_err_str(err));
        exit(EXIT_FAILURE);
    }

    server_np_num_per_na =
        s_ttp_conf.cpu.rt_server_np_num / s_ttp_conf.cpu.rt_server_na_num;
    for (i = 0; i < s_ttp_conf.cpu.rt_server_na_num; i++) {
        for (j = 0; j < server_np_num_per_na; j++) {
            if (0 != (err = ttp_delete_np((unsigned int)s_ttp_server_np_id[server_np_num_per_na * i + j]))) {
                fprintf(stderr, "failed to delete NP %d: %s\n",
                    (unsigned int)s_ttp_server_np_id[server_np_num_per_na * i + j], lune_get_err_str(err));
                exit(EXIT_FAILURE);
            }
        }

        if (0 != (err = ttp_delete_na((unsigned int)s_ttp_server_na_id[i]))) {
            fprintf(stderr, "failed to delete NA %d: %s\n",
                (unsigned int)s_ttp_server_na_id[i], lune_get_err_str(err));
            exit(EXIT_FAILURE);
        }
    }
}

static void ttp_create_client_na_np_net_if(void)
{
    int i, j;
    unsigned int client_np_num_per_na;
    unsigned int cp_avail, core_id;
    char cpu_list[TTP_CPU_LIST_MAX_BUF_LEN];
    lune_net_if_nrt_conf_t conf;
    lune_mac_addr_t start_mac;
    unsigned long long start_mac_ll;

    lune_assert(!lune_str_to_mac(TTP_CLIENT_START_MAC, start_mac));
    LUNE_MAC_TO_LL(start_mac, start_mac_ll);

    cp_avail = s_ttp_conf.cpu.rt_client_cp_num;
    client_np_num_per_na =
        s_ttp_conf.cpu.rt_client_np_num / s_ttp_conf.cpu.rt_client_na_num;
    for (i = 0; i < s_ttp_conf.cpu.rt_client_na_num; i++) {
        core_id = s_ttp_conf.cpu.rt_client_start + cp_avail + i;
        if (0 > (s_ttp_client_na_id[i] = ttp_create_na(core_id))) {
            fprintf(stderr, "failed to create client NA on core %d\n", core_id);
            exit(EXIT_FAILURE);
        }

        for (j = 0; j < client_np_num_per_na; j++) {
            strcat(cpu_list, ",");
            core_id = s_ttp_conf.cpu.rt_client_start
                + cp_avail + s_ttp_conf.cpu.rt_client_na_num + client_np_num_per_na * i + j;
            if (0 > (s_ttp_client_np_id[client_np_num_per_na * i + j] =
                ttp_create_np(core_id, 1, (unsigned int *)s_ttp_client_cp_id, cp_avail, i))) {
                fprintf(stderr, "failed to create client NP on core %d: %s\n",
                    core_id, lune_get_err_str(s_ttp_client_np_id[client_np_num_per_na * i + j]));
                exit(EXIT_FAILURE);
            }
        }
    }

    sprintf(cpu_list, "%d-%d", s_ttp_conf.cpu.rt_client_start + cp_avail,
        s_ttp_conf.cpu.rt_client_start + cp_avail + s_ttp_conf.cpu.rt_client_na_num
        + s_ttp_conf.cpu.rt_client_np_num - 1);

    if (LUNE_NET_IF_DPDK == s_ttp_conf.net_if.client.type) {
        lune_assert(1 == s_ttp_conf.cpu.rt_client_na_num);
        conf.dpdk_conf.txq_num = s_ttp_conf.cpu.rt_client_np_num;
        conf.aggr_conf.chan_type = LUNE_NET_IF_DPDK_CHAN;
    } else if (LUNE_NET_IF_DPDK_QUEUE == s_ttp_conf.net_if.client.type) {
        lune_assert(1 != s_ttp_conf.cpu.rt_client_na_num);
        conf.dpdk_queue_conf.rxq_num = s_ttp_conf.cpu.rt_client_na_num;
        conf.dpdk_queue_conf.txq_num = s_ttp_conf.cpu.rt_client_np_num;
        conf.dpdk_queue_conf.rss_type = LUNE_NET_IF_DPDK_RSS_TYPE_L3_DST;
        conf.aggr_conf.chan_type = LUNE_NET_IF_DPDK_QUEUE_CHAN;
    } else {
        conf.aggr_conf.chan_type = LUNE_NET_IF_CHAN;
    }
    conf.aggr_conf.conf.chan_num = s_ttp_conf.cpu.rt_client_np_num;
    conf.aggr_conf.conf.type = LUNE_NET_IF_AGGR_MAC_CLIENT;
    LUNE_LL_TO_MAC(start_mac_ll, conf.aggr_conf.conf.mac.start_mac);
    lune_assert(!(lune_str_to_mac(TTP_CLIENT_END_MAC, conf.aggr_conf.conf.mac.end_mac)));
    conf.aggr_conf.conf.mac.step = 1;
    conf.cpu_list = cpu_list;
    if (LUNE_INVALID_ID == (s_ttp_client_net_if_id = lune_add_net_if(s_ttp_conf.net_if.client.type,
            s_ttp_conf.net_if.client.name, &conf, sizeof(conf)))) {
        fprintf(stderr, "failed to add interface %s: %s\n",
            s_ttp_conf.net_if.client.name, lune_get_last_err_str());
        exit(EXIT_FAILURE);
    }
}

static void ttp_delete_client_na_np_net_if(void)
{
    int i, j, err;
    unsigned int client_np_num_per_na;

    if (0 != (err = lune_del_net_if(s_ttp_client_net_if_id))) {
        fprintf(stderr, "failed to delete interface %s: %s\n",
            s_ttp_conf.net_if.client.name, lune_get_err_str(err));
        exit(EXIT_FAILURE);
    }

    client_np_num_per_na =
        s_ttp_conf.cpu.rt_client_np_num / s_ttp_conf.cpu.rt_client_na_num;
    for (i = 0; i < s_ttp_conf.cpu.rt_client_na_num; i++) {
        for (j = 0; j < client_np_num_per_na; j++) {
            if (0 != (err = ttp_delete_np((unsigned int)s_ttp_client_np_id[client_np_num_per_na * i + j]))) {
                fprintf(stderr, "failed to delete NP %d: %s\n",
                    (unsigned int)s_ttp_server_np_id[client_np_num_per_na * i + j], lune_get_err_str(err));
                exit(EXIT_FAILURE);
            }
        }

        if (0 != (err = ttp_delete_na((unsigned int)s_ttp_client_na_id[i]))) {
            fprintf(stderr, "failed to delete NA %d: %s\n",
                (unsigned int)s_ttp_client_na_id[i], lune_get_err_str(err));
            exit(EXIT_FAILURE);
        }
    }
}

void run_ttp(void)
{
    int err;
    lune_conf_t conf;

    conf.id = s_ttp_conf.cpu.nrt;
    conf.log_file = "./ttp.log";
    conf.log_level = LUNE_VBS;
    if (0 != (err = lune_init(&conf))) {
        fprintf(stderr, "lune init failed: %s\n", lune_get_err_str(err));
        exit(EXIT_FAILURE);
    }

#ifdef LUNE_BUILD_SSL
    if (0 != (err = ttp_ssl_init())) {
        fprintf(stderr, "ssl init failed: %s\n", lune_get_err_str(err));
        exit(EXIT_FAILURE);
    }
#endif

    s_ttp_client_net_if_enable_flag = s_ttp_server_net_if_enable_flag = 0;
    s_ttp_start_flag = s_ttp_stop_flag = 0;

    if (s_ttp_conf.cpu.rt_server_cp_num > 0) {
        ttp_create_server_cp();
    }

    if (s_ttp_conf.cpu.rt_server_na_num > 0) {
        ttp_create_server_na_np_net_if();
    } else {
        ttp_create_server_np_net_if();
    }

    if (s_ttp_conf.cpu.rt_client_cp_num > 0) {
        ttp_create_client_cp();
    }

    if (s_ttp_conf.cpu.rt_client_na_num > 0) {
        ttp_create_client_na_np_net_if();
    } else {
        ttp_create_client_np_net_if();
    }

    ttp_connect_net_if();

    ttp_enable_server_net_if();

    ttp_enable_client_net_if();

    sleep(TTP_PRE_RUN_TIME_IN_SEC);

    /* test start */
    s_ttp_start_flag = 1;

    sleep(s_ttp_conf.load.time);

    /* test stop */
    s_ttp_stop_flag = 1;
    s_ttp_start_flag = 0;

    sleep(TTP_POST_RUN_TIME_IN_SEC);

    ttp_disable_client_net_if();

    ttp_disable_server_net_if();

    ttp_disconnect_net_if();

    if (s_ttp_conf.cpu.rt_client_na_num > 0) {
        ttp_delete_client_na_np_net_if();
    } else {
        ttp_delete_client_np_net_if();
    }

    if (s_ttp_conf.cpu.rt_client_cp_num > 0) {
        ttp_delete_client_cp();
    }

    if (s_ttp_conf.cpu.rt_server_na_num > 0) {
        ttp_delete_server_na_np_net_if();
    } else {
        ttp_delete_server_np_net_if();
    }

    if (s_ttp_conf.cpu.rt_server_cp_num > 0) {
        ttp_delete_server_cp();
    }

#ifdef LUNE_BUILD_SSL
    ttp_ssl_fini();
#endif

    lune_fini();
}
