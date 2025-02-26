/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2024 Lune Reseau, Inc.
 * 
 * Lune Test Interface Perf tool
 */

#include <yaml.h>

#include "lune/assert.h"
#include "lune/atomic.h"
#include "lune/err.h"
#include "lune/init.h"
#include "lune/ipv4.h"
#include "lune/core.h"
#include "lune/log.h"
#include "lune/mac.h"
#include "lune/net_if.h"
#include "lune/os/linux.h"
#include "lune/sched.h"
#include "lune/socket.h"
#include "lune/time.h"
#include "lune/timer.h"

#include "tip/tip.h"

#define TIP_CPU_LIST_MAX_BUF_LEN            (256)
#define TIP_CLIENT_MAC                      ("00:10:00:00:00:00")
#define TIP_CLIENT_IPV4_BASE                ("1.0.0.0")
#define TIP_SERVER_MAC                      ("00:10:00:00:04:00")
#define TIP_SERVER_IPV4                     ("2.0.0.0")
#define TIP_PRE_RUN_TIME_IN_SEC             (5)
#define TIP_POST_RUN_TIME_IN_SEC            (5)
#define TIP_AGGR_MAX_NP_NUM                 (32)
#define TIP_MAX_PKT_SIZE                    (1514)
#define TIP_MAX_TX_BURST_PKT_CNT            (2048)

/* tip parser section state */
#define TIP_PSS_CPU_STR                     "cpu"
#define TIP_PSS_CPU_NRT_STR                 "nrt"
#define TIP_PSS_CPU_RT_CLIENT_START_STR     "rt_client_start"
#define TIP_PSS_CPU_RT_CLIENT_CORE_NUM_STR  "rt_client_core_num"
#define TIP_PSS_CPU_RT_SERVER_START_STR     "rt_server_start"
#define TIP_PSS_CPU_RT_SERVER_CORE_NUM_STR  "rt_server_core_num"

#define TIP_PSS_NET_IF_STR                  "interface"
#define TIP_PSS_NET_IF_CLIENT_STR           "client"
#define TIP_PSS_NET_IF_CLIENT_NAME_STR      "name"
#define TIP_PSS_NET_IF_CLIENT_TYPE_STR      "type"
#define TIP_PSS_NET_IF_CLIENT_CAPTURE_STR   "capture"
#define TIP_PSS_NET_IF_SERVER_STR           "server"
#define TIP_PSS_NET_IF_SERVER_NAME_STR      "name"
#define TIP_PSS_NET_IF_SERVER_TYPE_STR      "type"
#define TIP_PSS_NET_IF_SERVER_CAPTURE_STR   "capture"

#define TIP_PSS_LOAD_STR                    "load"
#define TIP_PSS_LOAD_TIME_STR               "time"
#define TIP_PSS_LOAD_PPS_STR                "pps"
#define TIP_PSS_LOAD_PKT_SIZE_STR           "pkt_size"
#define TIP_PSS_LOAD_RESP_STR               "resp"

#define TIP_PSS_SYSTEM_STR                  "system"
#define TIP_PSS_SYSTEM_HZ_STR               "hz"

#define TIP_NET_IF_STD                      "standard"
#define TIP_NET_IF_DPDK                     "dpdk"
#define TIP_NET_IF_DPDK_QUEUE               "dpdk_queue"
#define TIP_NET_IF_VIRT                     "virtual"

#define TIP_OPTION_ENABLE                   "enable"
#define TIP_OPTION_DISABLE                  "disable"

/* tip configuration */
typedef struct _tip_conf {
    struct {
        unsigned int nrt;
        unsigned int rt_client_start;
        unsigned int rt_client_core_num;
        unsigned int rt_server_start;
        unsigned int rt_server_core_num;
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
        unsigned int pps;
        unsigned int pps_per_core;
        unsigned int pkt_size;
        unsigned int resp_enable;
    } load;
    struct {
        unsigned int hz;
    } system;
} tip_conf_t;

/* tip parser state */
typedef enum _tip_parser_state {
    TIP_PS_START,
    TIP_PS_ACCEPT_SECTION,
    TIP_PS_ACCEPT_LIST,
    TIP_PS_ACCEPT_KEY,
    TIP_PS_ACCEPT_VALUE,
    TIP_PS_STOP,
    TIP_PS_ERROR,
} tip_parser_state_en;

typedef enum _tip_parser_section_state {
    TIP_PSS_CPU,
    TIP_PSS_NET_IF,
    TIP_PSS_NET_IF_CLIENT,
    TIP_PSS_NET_IF_SERVER,
    TIP_PSS_LOAD,
    TIP_PSS_SYSTEM,
    TIP_PSS_NONE,
} tip_parser_section_state_en;

typedef struct _tip_parser_ins {
    tip_parser_state_en state;
    tip_parser_section_state_en sstate;
    int accepted;
    int error;
    char *key;
    char *value;
} tip_parser_ins_t;

static tip_conf_t s_tip_conf;
static __thread tip_conf_t s_tip_local_conf;

static __thread unsigned int s_tip_np_net_if_id;
static __thread unsigned int s_tip_np_run_task_id;
static __thread unsigned int s_tip_np_init_task_id;
static __thread unsigned int s_tip_np_net_if_socket_id;
static __thread unsigned char s_tip_np_net_if_send_buf[TIP_MAX_PKT_SIZE] = {0};
static __thread lune_timer_t s_tip_np_tmr;
static __thread lune_socket_send_pkt_t s_tip_np_tx_burst_pkts[TIP_MAX_TX_BURST_PKT_CNT];

static unsigned int s_tip_client_net_if_enable_flag;
static unsigned int s_tip_server_net_if_enable_flag;
static unsigned int s_tip_start_flag;
static unsigned int s_tip_stop_flag;

static int s_tip_client_np_id[TIP_AGGR_MAX_NP_NUM];
static unsigned int s_tip_client_net_if_id;
static int s_tip_server_np_id[TIP_AGGR_MAX_NP_NUM];
static unsigned int s_tip_server_net_if_id;

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

static int tip_process_cpu_event(tip_parser_ins_t *pi, yaml_event_t *ev)
{
    if (!strcmp(pi->key, TIP_PSS_CPU_NRT_STR)) {
        s_tip_conf.cpu.nrt = atoi(pi->value);
    } else if (!strcmp(pi->key, TIP_PSS_CPU_RT_CLIENT_START_STR)) {
        s_tip_conf.cpu.rt_client_start = atoi(pi->value);
    } else if (!strcmp(pi->key, TIP_PSS_CPU_RT_CLIENT_CORE_NUM_STR)) {
        s_tip_conf.cpu.rt_client_core_num = atoi(pi->value);
    } else if (!strcmp(pi->key, TIP_PSS_CPU_RT_SERVER_START_STR)) {
        s_tip_conf.cpu.rt_server_start = atoi(pi->value);
    } else if (!strcmp(pi->key, TIP_PSS_CPU_RT_SERVER_CORE_NUM_STR)) {
        s_tip_conf.cpu.rt_server_core_num = atoi(pi->value);
    } else {
        fprintf(stderr, "unknown key: %s\n", pi->key);
        pi->state = TIP_PS_ERROR;
        free(pi->key);
        return 0;
    }

    pi->state = TIP_PS_ACCEPT_KEY;

    free(pi->key);
    return 0;
}

static lune_net_if_type_en tip_convert_net_if_type(const char *type)
{
    if (!strcmp(type, TIP_NET_IF_STD)) {
        return LUNE_NET_IF_STD;
    } else if (!strcmp(type, TIP_NET_IF_DPDK)) {
        return LUNE_NET_IF_DPDK;
    } else if (!strcmp(type, TIP_NET_IF_DPDK_QUEUE)) {
        return LUNE_NET_IF_DPDK_QUEUE;
    } else if (!strcmp(type, TIP_NET_IF_VIRT)) {
        return LUNE_NET_IF_VIRT;
    } else {
        fprintf(stderr, "unknown interface type: %s\n", type);
        return LUNE_NET_IF_MAX;
    }
}

static int tip_process_net_if_event(tip_parser_ins_t *pi, yaml_event_t *ev)
{
    switch (pi->sstate) {
    case TIP_PSS_NET_IF:
        if (!strcmp((char*)ev->data.scalar.value, TIP_PSS_NET_IF_CLIENT_STR)) {
            pi->state = TIP_PS_ACCEPT_LIST;
            pi->sstate = TIP_PSS_NET_IF_CLIENT;
        } else if (!strcmp((char*)ev->data.scalar.value, TIP_PSS_NET_IF_SERVER_STR)) {
            pi->state = TIP_PS_ACCEPT_LIST;
            pi->sstate = TIP_PSS_NET_IF_SERVER;
        } else {
            fprintf(stderr, "unexpected scalar: %s\n", (char*)ev->data.scalar.value);
            pi->state = TIP_PS_ERROR;
        }
        break;
    case TIP_PSS_NET_IF_CLIENT:
        if (TIP_PS_ACCEPT_KEY == pi->state) {
            pi->state = TIP_PS_ACCEPT_VALUE;
            break;
        }

        if (!strcmp(pi->key, TIP_PSS_NET_IF_CLIENT_NAME_STR)) {
            strcpy(s_tip_conf.net_if.client.name, pi->value);
        } else if (!strcmp(pi->key, TIP_PSS_NET_IF_CLIENT_TYPE_STR)) {
            s_tip_conf.net_if.client.type = tip_convert_net_if_type(pi->value);
        } else if (!strcmp(pi->key, TIP_PSS_NET_IF_CLIENT_CAPTURE_STR)) {
            if (!strcmp(pi->value, TIP_OPTION_ENABLE)) {
                s_tip_conf.net_if.client.cap_enable = 1;
            } else if (!strcmp(pi->value, TIP_OPTION_DISABLE)) {
                s_tip_conf.net_if.client.cap_enable = 0;
            } else {
                fprintf(stderr, "invalid capture option: %s\n", pi->value);
                pi->state = TIP_PS_ERROR;
                break;
            }
        } else {
            fprintf(stderr, "unknown key: %s\n", pi->key);
            pi->state = TIP_PS_ERROR;
            break;
        }

        pi->state = TIP_PS_ACCEPT_KEY;
        break;
    case TIP_PSS_NET_IF_SERVER:
        if (TIP_PS_ACCEPT_KEY == pi->state) {
            pi->state = TIP_PS_ACCEPT_VALUE;
            break;
        }

        if (!strcmp(pi->key, TIP_PSS_NET_IF_SERVER_NAME_STR)) {
            strcpy(s_tip_conf.net_if.server.name, pi->value);
        } else if (!strcmp(pi->key, TIP_PSS_NET_IF_SERVER_TYPE_STR)) {
            s_tip_conf.net_if.server.type = tip_convert_net_if_type(pi->value);
        } else if (!strcmp(pi->key, TIP_PSS_NET_IF_SERVER_CAPTURE_STR)) {
            if (!strcmp(pi->value, TIP_OPTION_ENABLE)) {
                s_tip_conf.net_if.server.cap_enable = 1;
            } else if (!strcmp(pi->value, TIP_OPTION_DISABLE)) {
                s_tip_conf.net_if.server.cap_enable = 0;
            } else {
                fprintf(stderr, "invalid capture option: %s\n", pi->value);
                pi->state = TIP_PS_ERROR;
                break;
            }
        } else {
            fprintf(stderr, "unknown key: %s\n", pi->key);
            pi->state = TIP_PS_ERROR;
            break;
        }

        pi->state = TIP_PS_ACCEPT_KEY;
        break;
    default:
        fprintf(stderr, "unknown key: %s\n", pi->key);
        pi->state = TIP_PS_ERROR;
        break;
    }

    free(pi->key);
    return 0;
}

static int tip_process_load_event(tip_parser_ins_t *pi, yaml_event_t *ev)
{
    if (!strcmp(pi->key, TIP_PSS_LOAD_TIME_STR)) {
        s_tip_conf.load.time = atoi(pi->value);
    } else if (!strcmp(pi->key, TIP_PSS_LOAD_PPS_STR)) {
        s_tip_conf.load.pps = atoi(pi->value);
    } else if (!strcmp(pi->key, TIP_PSS_LOAD_PKT_SIZE_STR)) {
        s_tip_conf.load.pkt_size = atoi(pi->value);
        if (s_tip_conf.load.pkt_size > TIP_MAX_PKT_SIZE) {
            fprintf(stderr, "invalid payload size: %s\n", pi->value);
            return 0;
        }
    } else if (!strcmp(pi->key, TIP_PSS_LOAD_RESP_STR)) {
        if (!strcmp(pi->value, TIP_OPTION_ENABLE)) {
            s_tip_conf.load.resp_enable = 1;
        } else if (!strcmp(pi->value, TIP_OPTION_DISABLE)) {
            s_tip_conf.load.resp_enable = 0;
        } else {
            fprintf(stderr, "invalid response option: %s\n", pi->value);
            pi->state = TIP_PS_ERROR;
            return 0;
        }
    } else {
        fprintf(stderr, "unknown key: %s\n", pi->key);
        pi->state = TIP_PS_ERROR;
        free(pi->key);
        return 0;
    }

    pi->state = TIP_PS_ACCEPT_KEY;

    free(pi->key);
    return 0;
}

static int tip_process_system_event(tip_parser_ins_t *pi, yaml_event_t *ev)
{
    if (!strcmp(pi->key, TIP_PSS_SYSTEM_HZ_STR)) {
        s_tip_conf.system.hz = atoi(pi->value);
    } else {
        fprintf(stderr, "unknown key: %s\n", pi->key);
        pi->state = TIP_PS_ERROR;
        free(pi->key);
        return 0;
    }

    pi->state = TIP_PS_ACCEPT_KEY;

    free(pi->key);
    return 0;
}

static int tip_process_event(tip_parser_ins_t *pi, yaml_event_t *ev)
{
    pi->accepted = 0;
    switch (pi->state) {
    case TIP_PS_START:
        switch (ev->type) {
        case YAML_MAPPING_START_EVENT:
            pi->state = TIP_PS_ACCEPT_SECTION;
            break;
        case YAML_SCALAR_EVENT:
            fprintf(stderr, "unexpected scalar: %s\n", (char*)ev->data.scalar.value);
            pi->state = TIP_PS_ERROR;
            break;
        case YAML_STREAM_END_EVENT:
            pi->state = TIP_PS_STOP;
            break;
        default:
            break;
        }
        break;
    case TIP_PS_ACCEPT_SECTION:
        switch (ev->type) {
        case YAML_SCALAR_EVENT:
            if (!strcmp((char*)ev->data.scalar.value, TIP_PSS_CPU_STR)) {
                pi->state = TIP_PS_ACCEPT_LIST;
                pi->sstate = TIP_PSS_CPU;
            } else if (!strcmp((char*)ev->data.scalar.value, TIP_PSS_NET_IF_STR)) {
                pi->state = TIP_PS_ACCEPT_LIST;
                pi->sstate = TIP_PSS_NET_IF;
            } else if (!strcmp((char*)ev->data.scalar.value, TIP_PSS_LOAD_STR)) {
                pi->state = TIP_PS_ACCEPT_LIST;
                pi->sstate = TIP_PSS_LOAD;
            } else if (!strcmp((char*)ev->data.scalar.value, TIP_PSS_SYSTEM_STR)) {
                pi->state = TIP_PS_ACCEPT_LIST;
                pi->sstate = TIP_PSS_SYSTEM;
            } else {
                fprintf(stderr, "unexpected scalar: %s\n", (char*)ev->data.scalar.value);
                pi->state = TIP_PS_ERROR;
            }
            break;
        case YAML_MAPPING_END_EVENT:
            break;
        case YAML_DOCUMENT_END_EVENT:
            pi->accepted = 1;
            pi->state = TIP_PS_START;
            break;
        default:
            fprintf(stderr, "unexpected event while getting scalar: %d\n", ev->type);
            pi->state = TIP_PS_ERROR;
            break;
        }
        break;
    case TIP_PS_ACCEPT_LIST:
        switch (ev->type) {
        case YAML_MAPPING_START_EVENT:
            pi->state = TIP_PS_ACCEPT_KEY;
            break;
        default:
            fprintf(stderr, "unexpected event while getting list: %d\n", ev->type);
            pi->state = TIP_PS_ERROR;
            break;
        }
        break;
    case TIP_PS_ACCEPT_KEY:
        switch (ev->type) {
        case YAML_SCALAR_EVENT:
            pi->key = strdup((char*)ev->data.scalar.value);
            switch (pi->sstate) {
            case TIP_PSS_CPU:
            case TIP_PSS_NET_IF_CLIENT:
            case TIP_PSS_NET_IF_SERVER:
            case TIP_PSS_LOAD:
            case TIP_PSS_SYSTEM:
                pi->state = TIP_PS_ACCEPT_VALUE;
                break;
            case TIP_PSS_NET_IF:
                (void)tip_process_net_if_event(pi, ev);
                break;
            default:
                fprintf(stderr, "unexpected event while getting key: %d\n", ev->type);
                pi->state = TIP_PS_ERROR;
                break;
            }
            break;
        case YAML_MAPPING_END_EVENT:
            switch (pi->sstate) {
            case TIP_PSS_CPU:
            case TIP_PSS_NET_IF:
            case TIP_PSS_LOAD:
            case TIP_PSS_SYSTEM:
                pi->state = TIP_PS_ACCEPT_SECTION;
                break;
            case TIP_PSS_NET_IF_CLIENT:
            case TIP_PSS_NET_IF_SERVER:
                pi->state = TIP_PS_ACCEPT_KEY;
                pi->sstate = TIP_PSS_NET_IF;
                break;
            default:
                fprintf(stderr, "unexpected event while getting key: %d\n", ev->type);
                pi->state = TIP_PS_ERROR;
                break;
            }
            break;
        default:
            fprintf(stderr, "unexpected event while getting key: %d\n", ev->type);
            pi->state = TIP_PS_ERROR;
            break;
        }
        break;
    case TIP_PS_ACCEPT_VALUE:
        switch (ev->type) {
        case YAML_SCALAR_EVENT:
            pi->value = (char*)ev->data.scalar.value;
            switch (pi->sstate) {
            case TIP_PSS_CPU:
                (void)tip_process_cpu_event(pi, ev);
                break;
            case TIP_PSS_NET_IF_CLIENT:
            case TIP_PSS_NET_IF_SERVER:
                (void)tip_process_net_if_event(pi, ev);
                break;
            case TIP_PSS_LOAD:
                (void)tip_process_load_event(pi, ev);
                break;
            case TIP_PSS_SYSTEM:
                (void)tip_process_system_event(pi, ev);
                break;
            default:
                break;
            }
            break;
        case YAML_MAPPING_START_EVENT:
            pi->state = TIP_PS_ACCEPT_KEY;
            break;
        case YAML_DOCUMENT_END_EVENT:
            pi->state = TIP_PS_START;
            break;
        default:
            fprintf(stderr, "unexpected event while getting value: %d\n", ev->type);
            pi->state = TIP_PS_ERROR;
            break;
        }
        break;
    case TIP_PS_ERROR:
    case TIP_PS_STOP:
        break;
    }

    return (pi->state == TIP_PS_ERROR ? 0 : 1);
}

static int tip_validate_conf(void)
{
    if (s_tip_conf.cpu.rt_client_core_num > 1
        && s_tip_conf.net_if.client.type != LUNE_NET_IF_DPDK_QUEUE) {
        fprintf(stderr, "invalid NP number for interface %s: %d\n",
            s_tip_conf.net_if.client.name, s_tip_conf.cpu.rt_client_core_num);
        return -1;
    }

    if (s_tip_conf.cpu.rt_server_core_num > 1
        && s_tip_conf.net_if.server.type != LUNE_NET_IF_DPDK_QUEUE) {
        fprintf(stderr, "invalid NP number for interface %s: %d\n",
            s_tip_conf.net_if.server.name, s_tip_conf.cpu.rt_server_core_num);
        return -1;
    }

    return 0;
}

int tip_parse_conf_file(const char *tip_conf_file)
{
    yaml_parser_t parser;
    yaml_event_t ev;
    tip_parser_ins_t pi = {.state = TIP_PS_START, .sstate = TIP_PSS_NONE, .accepted = 0, .error = 0};
    FILE *fp;

    if (NULL == (fp = fopen(tip_conf_file, "r"))) {
        fprintf(stderr, "failed to open config file: %s\n", tip_conf_file);
        return -1;
    }

    memset(&s_tip_conf, 0xff, sizeof(s_tip_conf));
    yaml_parser_initialize(&parser);
    yaml_parser_set_input_file(&parser, fp);

    do {
        if (!yaml_parser_parse(&parser, &ev)) {
            goto ERR;
        }

        if (!tip_process_event(&pi, &ev)) {
            goto ERR;
        }

        if (pi.accepted) {
            fprintf(stdout, "load %s complete\n", tip_conf_file);
        }

        yaml_event_delete(&ev);
    } while (pi.state != TIP_PS_STOP);

    if (tip_validate_conf()) {
        return -1;
    }

    s_tip_conf.load.pps_per_core = s_tip_conf.load.pps / s_tip_conf.cpu.rt_client_core_num;

    yaml_parser_delete(&parser);
    return 0;

ERR:
    yaml_parser_delete(&parser);
    fclose(fp);
    return -1;
}

static void tip_np_net_if_stats_func(void *data)
{
    static __thread unsigned int sec = 0;
    lune_net_if_stats_t stats;
    int err;

    if (0 != (err = lune_get_net_if_opt(s_tip_np_net_if_id,
        LUNE_NET_IF_OPT_GET_STATS, &stats, sizeof(stats)))) {
        if (-LUNE_ERR_ID_NOT_FOUND != err) {
            lune_log(LUNE_INFO, "[TIP] failed to get statistics of interface %d: %s",
                s_tip_np_net_if_id, lune_get_err_str(err));
        }

        return;
    }

    sec++;

    lune_log(LUNE_DBG, "[TIP] %d sec: "
        "Tx_pkt %.2fM "
        "Tx_pps %.2fM "
        "Tx_byte %.2fM "
        "Tx_bps %.2fM "
        "Rx_pkt %.2fM "
        "Rx_pps %.2fM "
        "Rx_byte %.2fM "
        "Rx_bps %.2fM",
        sec,
        (float)stats.pkt_out / 1000000,
        (float)stats.pkt_out_rate / 1000000,
        (float)stats.byte_out / 1000000,
        (float)stats.byte_out_rate * 8 / 1000000,
        (float)stats.pkt_in / 1000000,
        (float)stats.pkt_in_rate / 1000000,
        (float)stats.byte_in / 1000000,
        (float)stats.byte_in_rate * 8 / 1000000);
}

static void tip_client_np_run(void *data)
{
    int cnt, err;
    static __thread unsigned int tick = 0;
    lune_ipv4_hdr_t *ipv4h;

    if (s_tip_stop_flag) {
        lune_assert(!lune_del_task(s_tip_np_run_task_id));
        s_tip_np_run_task_id = LUNE_INVALID_ID;

        lune_assert(!lune_close(s_tip_np_net_if_socket_id));
        s_tip_np_net_if_socket_id = LUNE_INVALID_ID;

        lune_log(LUNE_INFO, "client NP stopping");
        return;
    }

    if (!s_tip_start_flag) {
        return;
    }

    if (0 == tick) {
        lune_log(LUNE_INFO, "client NP starting");
    }

    tick++;
    if (s_tip_local_conf.load.pps_per_core < LUNE_TIME_GET_HZ()) {
        if (0 == s_tip_local_conf.load.pps_per_core
            || 0 != (tick % (LUNE_TIME_GET_HZ() / s_tip_local_conf.load.pps_per_core))) {
            return;
        }
        cnt = 1;
    } else {
        cnt = s_tip_local_conf.load.pps_per_core / LUNE_TIME_GET_HZ();
        lune_assert(cnt <= TIP_MAX_TX_BURST_PKT_CNT);
    }

    ipv4h = (lune_ipv4_hdr_t *)(s_tip_np_net_if_send_buf + LUNE_ETH_HDR_LEN);
    *((unsigned char *)&ipv4h->src_addr + 3) += 1;

    if (0 > (err = lune_send_pkts(s_tip_np_net_if_socket_id,
        s_tip_np_tx_burst_pkts, cnt, LUNE_SOCKET_SEND_PKTS_UNCHANGED))) {
        lune_log(LUNE_DBG, "[TIP] failed to send %d packets: %s",
            cnt, lune_get_last_err_str());
    } else {
        if (err != cnt) {
            lune_log(LUNE_DBG, "[TIP] %d packets sent (%d expected)",
                err, cnt);
        }
    }
}

static void tip_client_np_init(void *data)
{
    int err;
    lune_eth_hdr_t *ethh;
    lune_ipv4_hdr_t *ipv4h;

    if (!s_tip_client_net_if_enable_flag) {
        /* interface not added or not enabled yet */
        return;
    }

    lune_assert(!lune_init_timer(&s_tip_np_tmr,
        LUNE_TIMER_RECURRING, LUNE_TIMER_RES_DEFAULT, tip_np_net_if_stats_func, NULL));
    if (data) {
        lune_assert(!lune_add_timer(&s_tip_np_tmr, 1 * LUNE_TIME_SECOND));
    }

    if (LUNE_INVALID_ID == (s_tip_np_net_if_socket_id = lune_socket(LUNE_SOCKET_NET_IF))) {
        lune_log(LUNE_INFO, "[TIP] failed to create socket: %s",
            lune_get_last_err_str());
        goto ERR_1;
    }

    if (0 != (err = lune_bind(s_tip_np_net_if_socket_id,
        (void *)&s_tip_np_net_if_id, sizeof(s_tip_np_net_if_id)))) {
        lune_log(LUNE_INFO, "[TIP] failed to bind socket: %s",
            lune_get_err_str(err));
        goto ERR_2;
    }

    ethh = (lune_eth_hdr_t *)s_tip_np_net_if_send_buf;
    lune_assert(!lune_str_to_mac(TIP_CLIENT_MAC, ethh->src_mac));
    lune_assert(!lune_str_to_mac(TIP_SERVER_MAC, ethh->dst_mac));
    ethh->type = lune_htons(LUNE_ETH_TYPE_IPV4);

    ipv4h = (lune_ipv4_hdr_t *)(s_tip_np_net_if_send_buf + LUNE_ETH_HDR_LEN);
    lune_assert(!lune_str_to_ipv4(TIP_CLIENT_IPV4_BASE, &ipv4h->src_addr));
    ipv4h->src_addr += lune_core_get_id();
    ipv4h->src_addr = lune_htonl(ipv4h->src_addr);
    lune_assert(!lune_str_to_ipv4(TIP_SERVER_IPV4, &ipv4h->dst_addr));
    ipv4h->dst_addr = lune_htonl(ipv4h->dst_addr);

    ipv4h->ver_len = 0x40 + (LUNE_IPV4_HDR_LEN >> 2);
    ipv4h->tos = 0;
    ipv4h->total_len = lune_htons(s_tip_local_conf.load.pkt_size - LUNE_ETH_HDR_LEN);
    ipv4h->id = 0;
    ipv4h->offset = lune_htons(LUNE_IPV4_FLAG_DF);
    ipv4h->ttl = 128;
    ipv4h->proto = 0;
    ipv4h->csum = 0;

    lune_assert(LUNE_INVALID_ID != (s_tip_np_run_task_id =
        lune_add_task("tip client NP run", tip_client_np_run, NULL, LUNE_TASK_PRIO_HIGH)));

    lune_assert(!lune_del_task(s_tip_np_init_task_id));
    s_tip_np_init_task_id = LUNE_INVALID_ID;
    return;

ERR_2:
    lune_assert(!lune_close(s_tip_np_net_if_socket_id));
    s_tip_np_net_if_socket_id = LUNE_INVALID_ID;

ERR_1:
    lune_assert(!lune_del_timer(&s_tip_np_tmr));

    lune_assert(!lune_del_task(s_tip_np_init_task_id));
    s_tip_np_init_task_id = LUNE_INVALID_ID;
}

static int __tip_client_np_init(void *data)
{
    int i;

    memcpy(&s_tip_local_conf, &s_tip_conf, sizeof(s_tip_conf));

    s_tip_np_net_if_id = s_tip_client_net_if_id;
    s_tip_np_net_if_socket_id = LUNE_INVALID_ID;
    s_tip_np_run_task_id = LUNE_INVALID_ID;
    for (i = 0; i < TIP_MAX_TX_BURST_PKT_CNT; i++) {
        s_tip_np_tx_burst_pkts[i].buf = s_tip_np_net_if_send_buf;
        s_tip_np_tx_burst_pkts[i].len = s_tip_local_conf.load.pkt_size;
    }

    if (LUNE_INVALID_ID == (s_tip_np_init_task_id =
        lune_add_task("tip client NP init", tip_client_np_init, data, LUNE_TASK_PRIO_HIGH))) {
        return lune_get_err_no();
    }

    return 0;
}

static void __tip_client_np_fini(void)
{
    lune_assert(0 == s_tip_np_net_if_id);
    lune_assert(LUNE_INVALID_ID == s_tip_np_init_task_id);

    if (LUNE_TIMER_IS_ADDED(s_tip_np_tmr)) {
        lune_assert(!lune_del_timer(&s_tip_np_tmr));
    }

    if (LUNE_INVALID_ID != s_tip_np_run_task_id) {
        lune_assert(!lune_del_task(s_tip_np_run_task_id));
        s_tip_np_run_task_id = LUNE_INVALID_ID;
    }

    if (LUNE_INVALID_ID != s_tip_np_net_if_socket_id) {
        lune_assert(!lune_close(s_tip_np_net_if_socket_id));
        s_tip_np_net_if_socket_id = LUNE_INVALID_ID;
    }
}

static int tip_server_np_net_if_socket_recv(void *data,
    const unsigned char *buf, unsigned int len)
{
    int err;
    lune_eth_hdr_t *ethh;
    lune_mac_addr_t mac;
    lune_ipv4_hdr_t *ipv4h;
    lune_ipv4_addr_t ipv4;

    ethh = (lune_eth_hdr_t *)buf;
    ipv4h = (lune_ipv4_hdr_t *)(buf + LUNE_ETH_HDR_LEN);

    /* swap source and destination mac address */
    LUNE_MAC_CPY(mac, ethh->src_mac);
    LUNE_MAC_CPY(ethh->src_mac, ethh->dst_mac);
    LUNE_MAC_CPY(ethh->dst_mac, mac);

    /* swap source and destination ipv4 address */
    ipv4 = ipv4h->src_addr;
    ipv4h->src_addr = ipv4h->dst_addr;
    ipv4h->dst_addr = ipv4;

    if (0 != (err = lune_send_in_cb(buf, len))) {
        lune_log_once(LUNE_DBG, "[TIP] failed to send packet: %s", lune_get_err_str(err));
    }

    return 0;
}

static void tip_server_np_run(void *data)
{
    static __thread unsigned int tick = 0;

    if (s_tip_stop_flag) {
        lune_assert(!lune_del_task(s_tip_np_run_task_id));
        s_tip_np_run_task_id = LUNE_INVALID_ID;

        lune_assert(!lune_close(s_tip_np_net_if_socket_id));
        s_tip_np_net_if_socket_id = LUNE_INVALID_ID;

        lune_log(LUNE_INFO, "server NP stopping");
        return;
    }

    if (!s_tip_start_flag) {
        return;
    }

    if (0 == tick) {
        lune_log(LUNE_INFO, "server NP starting");
    }

    tick++;
}

static void tip_server_np_init(void *data)
{
    int err;
    lune_net_if_socket_callback_t cb;

    if (!s_tip_server_net_if_enable_flag) {
        /* interface not added or not enabled yet */
        return;
    }

    lune_assert(!lune_init_timer(&s_tip_np_tmr,
        LUNE_TIMER_RECURRING, LUNE_TIMER_RES_DEFAULT, tip_np_net_if_stats_func, NULL));
    if (data) {
        lune_assert(!lune_add_timer(&s_tip_np_tmr, 1 * LUNE_TIME_SECOND));
    }

    if (LUNE_INVALID_ID == (s_tip_np_net_if_socket_id = lune_socket(LUNE_SOCKET_NET_IF))) {
        lune_log(LUNE_INFO, "[TIP] failed to create socket: %s",
            lune_get_last_err_str());
        goto ERR_1;
    }

    if (0 != (err = lune_bind(s_tip_np_net_if_socket_id,
        (void *)&s_tip_np_net_if_id, sizeof(s_tip_np_net_if_id)))) {
        lune_log(LUNE_INFO, "[TIP] failed to bind socket: %s",
            lune_get_err_str(err));
        goto ERR_2;
    }


    if (s_tip_local_conf.load.resp_enable) {
        cb.recv = tip_server_np_net_if_socket_recv;
    } else {
        cb.recv = NULL;
    }
    cb.data = NULL;
    if (0 != (err = lune_set_socket_opt(s_tip_np_net_if_socket_id,
        LUNE_SOCKET_OPT_SET_CALLBACK, (void *)&cb, sizeof(cb)))) {
        lune_log(LUNE_INFO, "[TIP] failed to set callback on socket: %s",
            lune_get_err_str(err));
        goto ERR_2;
    }

    lune_assert(LUNE_INVALID_ID != (s_tip_np_run_task_id =
        lune_add_task("tip server NP run", tip_server_np_run, NULL, LUNE_TASK_PRIO_HIGH)));

    lune_assert(!lune_del_task(s_tip_np_init_task_id));
    s_tip_np_init_task_id = LUNE_INVALID_ID;
    return;

ERR_2:
    lune_assert(!lune_close(s_tip_np_net_if_socket_id));
    s_tip_np_net_if_socket_id = LUNE_INVALID_ID;

ERR_1:
    lune_assert(!lune_del_timer(&s_tip_np_tmr));

    lune_assert(!lune_del_task(s_tip_np_init_task_id));
    s_tip_np_init_task_id = LUNE_INVALID_ID;
}

static int __tip_server_np_init(void *data)
{
    memcpy(&s_tip_local_conf, &s_tip_conf, sizeof(s_tip_conf));

    s_tip_np_net_if_id = s_tip_server_net_if_id;
    s_tip_np_net_if_socket_id = LUNE_INVALID_ID;
    s_tip_np_run_task_id = LUNE_INVALID_ID;

    if (LUNE_INVALID_ID == (s_tip_np_init_task_id =
        lune_add_task("tip server NP init", tip_server_np_init, data, LUNE_TASK_PRIO_HIGH))) {
        return lune_get_err_no();
    }

    return 0;
}

static void __tip_server_np_fini(void)
{
    lune_assert(0 == s_tip_np_net_if_id);
    lune_assert(LUNE_INVALID_ID == s_tip_np_init_task_id);

    if (LUNE_TIMER_IS_ADDED(s_tip_np_tmr)) {
        lune_assert(!lune_del_timer(&s_tip_np_tmr));
    }

    if (LUNE_INVALID_ID != s_tip_np_run_task_id) {
        lune_assert(!lune_del_task(s_tip_np_run_task_id));
        s_tip_np_run_task_id = LUNE_INVALID_ID;
    }

    if (LUNE_INVALID_ID != s_tip_np_net_if_socket_id) {
        lune_assert(!lune_close(s_tip_np_net_if_socket_id));
        s_tip_np_net_if_socket_id = LUNE_INVALID_ID;
    }
}

static int tip_create_np(unsigned int core_id,
    unsigned int is_client, unsigned int hz, unsigned int first)
{
    lune_core_conf_t conf;
    int id, err;
    unsigned int sleep_usecs = 500;

    conf.id = core_id;
    conf.type = LUNE_CORE_NP;
    conf.hz = hz;
    conf.log_level = LUNE_DBG;
    sprintf(conf.log_file, "./tip_np_%d.log", core_id);
    if (is_client) {
        conf.task.init = __tip_client_np_init;
        conf.task.fini = __tip_client_np_fini;
        conf.task.data = first ? (void *)1: NULL;
    } else {
        conf.task.init = __tip_server_np_init;
        conf.task.fini = __tip_server_np_fini;
        conf.task.data = first ? (void *)1: NULL;
    }
    if (first) {
        first = 0;
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

    /* suppress cpu usage log occurring on regular basis */
    if (0 != lune_set_core_opt(core_id,
        LUNE_CORE_OPT_SET_LOG_CPU_USAGE_OFF, NULL, 0)) {
        return lune_get_err_no();
    }

    return id;
}

static int tip_delete_np(unsigned int id)
{
    return lune_delete_core(id);
}

static void tip_create_server_net_if(void)
{
    unsigned int i, core_id;
    lune_net_if_nrt_conf_t conf;
    char cpu_list[TIP_CPU_LIST_MAX_BUF_LEN];

    for (i = 0; i < s_tip_conf.cpu.rt_server_core_num; i++) {
        core_id = s_tip_conf.cpu.rt_server_start + i;

        if (0 > (s_tip_server_np_id[i] = tip_create_np(core_id,
            0, s_tip_conf.system.hz, 0 == i ? 1 : 0))) {
            fprintf(stderr, "failed to create server NP %d for %s: %s\n",
                core_id,
                s_tip_conf.net_if.server.name,
                lune_get_err_str(s_tip_server_np_id[i]));
            exit(EXIT_FAILURE);
        }
    }
    sprintf(cpu_list, "%d-%d", s_tip_conf.cpu.rt_server_start,
        s_tip_conf.cpu.rt_server_start + s_tip_conf.cpu.rt_server_core_num - 1);

    if (LUNE_NET_IF_DPDK == s_tip_conf.net_if.server.type) {
        conf.dpdk_conf.txq_num = s_tip_conf.cpu.rt_server_core_num;
    } else if (LUNE_NET_IF_DPDK_QUEUE == s_tip_conf.net_if.server.type) {
        conf.dpdk_queue_conf.rxq_num =
            conf.dpdk_queue_conf.txq_num = s_tip_conf.cpu.rt_server_core_num;
        conf.dpdk_queue_conf.rss_type = LUNE_NET_IF_DPDK_RSS_TYPE_L3_SRC;
    }
    conf.cpu_list = cpu_list;
    if (LUNE_INVALID_ID == (s_tip_server_net_if_id = lune_add_net_if(s_tip_conf.net_if.server.type,
        s_tip_conf.net_if.server.name, &conf, sizeof(conf)))) {
        fprintf(stderr, "failed to add interface %s: %s\n",
            s_tip_conf.net_if.server.name, lune_get_last_err_str());
        exit(EXIT_FAILURE);
    }
}

static void tip_delete_server_net_if(void)
{
    int i, err;

    if (0 != (err = lune_del_net_if(s_tip_server_net_if_id))) {
        fprintf(stderr, "failed to delete interface %d: %s\n",
            s_tip_server_net_if_id, lune_get_err_str(err));
        exit(EXIT_FAILURE);
    }

    for (i = 0; i < s_tip_conf.cpu.rt_server_core_num; i++) {
        if (0 != (err = tip_delete_np((unsigned int)s_tip_server_np_id[i]))) {
            fprintf(stderr, "failed to delete NP %d: %s\n",
                (unsigned int)s_tip_server_np_id[i], lune_get_err_str(err));
            exit(EXIT_FAILURE);
        }
    }
}

static void tip_enable_server_net_if(void)
{
    int err;

    if (LUNE_NET_IF_DPDK_QUEUE == s_tip_conf.net_if.server.type) {
        /* clear default setting of auto packet distribution on queues for performance's sake */
        if (0 != (err = lune_set_net_if_opt(s_tip_server_net_if_id,
            LUNE_NET_IF_OPT_DPDK_QUEUE_CLEAR_DISTRIB, NULL, 0))) {
            fprintf(stderr, "failed to clear distribution on interface %s: %s\n",
                s_tip_conf.net_if.server.name, lune_get_err_str(err));
            exit(EXIT_FAILURE);
        }
    }

    if (0 != (err = lune_enable_net_if(s_tip_server_net_if_id))) {
        fprintf(stderr, "failed to enable interface %s: %s\n",
            s_tip_conf.net_if.server.name, lune_get_err_str(err));
        exit(EXIT_FAILURE);
    }

    s_tip_server_net_if_enable_flag = 1;

    if (s_tip_conf.net_if.server.cap_enable) {
        char cap_file[LUNE_MAX_LONG_NAME_BUF_LEN];
        lune_net_if_pcap_t pcap;

        sprintf(cap_file, "./tip_np_%s.pcap", s_tip_conf.net_if.server.name);
        lune_str_replace_char(cap_file, ':', '_');

        pcap.file_name = cap_file;
        if (0 != (err = lune_set_net_if_opt(s_tip_server_net_if_id,
            LUNE_NET_IF_OPT_PCAP_START, &pcap, sizeof(pcap)))) {
            fprintf(stderr, "failed to capture packet on interface %s: %s\n",
                s_tip_conf.net_if.server.name, lune_get_err_str(err));
        }

#if 0
        if (LUNE_NET_IF_DPDK_QUEUE == s_tip_conf.net_if.server.type) {
            /* capture packets on all queues */
            if (0 != (err = lune_set_net_if_opt(s_tip_server_net_if_id,
                LUNE_NET_IF_OPT_DPDK_QUEUE_PCAP_START, NULL, 0))) {
                fprintf(stderr, "failed to capture packet on interface %s: %s\n",
                    s_tip_conf.net_if.server.name, lune_get_err_str(err));
                exit(EXIT_FAILURE);
            }
        }
#endif
    }
}

static void tip_disable_server_net_if(void)
{
    int err;

    if (0 != (err = lune_disable_net_if(s_tip_server_net_if_id))) {
        fprintf(stderr, "failed to disable interface %d: %s\n",
            s_tip_server_net_if_id, lune_get_err_str(err));
        exit(EXIT_FAILURE);
    }
}

static void tip_create_client_net_if(void)
{
    unsigned int i, core_id;
    lune_net_if_nrt_conf_t conf;
    char cpu_list[TIP_CPU_LIST_MAX_BUF_LEN];

    for (i = 0; i < s_tip_conf.cpu.rt_client_core_num; i++) {
        core_id = s_tip_conf.cpu.rt_client_start + i;

        if (0 > (s_tip_client_np_id[i] = tip_create_np(core_id,
            1, s_tip_conf.system.hz, 0 == i ? 1 : 0))) {
            fprintf(stderr, "failed to create client NP %d for %s: %s\n",
                core_id,
                s_tip_conf.net_if.client.name,
                lune_get_err_str(s_tip_client_np_id[i]));
            exit(EXIT_FAILURE);
        }
    }
    sprintf(cpu_list, "%d-%d", s_tip_conf.cpu.rt_client_start,
        s_tip_conf.cpu.rt_client_start + s_tip_conf.cpu.rt_client_core_num - 1);

    if (LUNE_NET_IF_DPDK == s_tip_conf.net_if.client.type) {
        conf.dpdk_conf.txq_num = s_tip_conf.cpu.rt_client_core_num;
    } else if (LUNE_NET_IF_DPDK_QUEUE == s_tip_conf.net_if.client.type) {
        conf.dpdk_queue_conf.rxq_num =
            conf.dpdk_queue_conf.txq_num = s_tip_conf.cpu.rt_client_core_num;
        conf.dpdk_queue_conf.rss_type = LUNE_NET_IF_DPDK_RSS_TYPE_L3_DST;
    }
    conf.cpu_list = cpu_list;
    if (LUNE_INVALID_ID == (s_tip_client_net_if_id = lune_add_net_if(s_tip_conf.net_if.client.type,
        s_tip_conf.net_if.client.name, &conf, sizeof(conf)))) {
        fprintf(stderr, "failed to add interface %s: %s\n",
            s_tip_conf.net_if.client.name, lune_get_last_err_str());
        exit(EXIT_FAILURE);
    }
}

static void tip_delete_client_net_if(void)
{
    int i, err;

    if (0 != (err = lune_del_net_if(s_tip_client_net_if_id))) {
        fprintf(stderr, "failed to delete interface %d: %s\n",
            s_tip_client_net_if_id, lune_get_err_str(err));
        exit(EXIT_FAILURE);
    }

    for (i = 0; i < s_tip_conf.cpu.rt_client_core_num; i++) {
        if (0 != (err = tip_delete_np((unsigned int)s_tip_client_np_id[i]))) {
            fprintf(stderr, "failed to delete NP %d: %s\n",
                (unsigned int)s_tip_client_np_id[i], lune_get_err_str(err));
            exit(EXIT_FAILURE);
        }
    }
}

static void tip_enable_client_net_if(void)
{
    int err;

    if (LUNE_NET_IF_DPDK_QUEUE == s_tip_conf.net_if.client.type) {
        /* clear default setting of auto packet distribution on queues for performance's sake */
        if (0 != (err = lune_set_net_if_opt(s_tip_client_net_if_id,
            LUNE_NET_IF_OPT_DPDK_QUEUE_CLEAR_DISTRIB, NULL, 0))) {
            fprintf(stderr, "failed to clear distribution on interface %s: %s\n",
                s_tip_conf.net_if.client.name, lune_get_err_str(err));
            exit(EXIT_FAILURE);
        }
    }

    if (0 != (err = lune_enable_net_if(s_tip_client_net_if_id))) {
        fprintf(stderr, "failed to enable interface %s: %s\n",
            s_tip_conf.net_if.client.name, lune_get_err_str(err));
        exit(EXIT_FAILURE);
    }

    s_tip_client_net_if_enable_flag = 1;

    if (s_tip_conf.net_if.client.cap_enable) {
        char cap_file[LUNE_MAX_LONG_NAME_BUF_LEN];
        lune_net_if_pcap_t pcap;

        sprintf(cap_file, "./tip_np_%s.pcap", s_tip_conf.net_if.client.name);
        lune_str_replace_char(cap_file, ':', '_');

        pcap.file_name = cap_file;
        if (0 != (err = lune_set_net_if_opt(s_tip_client_net_if_id,
            LUNE_NET_IF_OPT_PCAP_START, &pcap, sizeof(pcap)))) {
            fprintf(stderr, "failed to capture packet on interface %s: %s\n",
                s_tip_conf.net_if.client.name, lune_get_err_str(err));
        }

#if 0
        if (LUNE_NET_IF_DPDK_QUEUE == s_tip_conf.net_if.client.type) {
            /* capture packets on all queues */
            if (0 != (err = lune_set_net_if_opt(s_tip_client_net_if_id,
                LUNE_NET_IF_OPT_DPDK_QUEUE_PCAP_START, NULL, 0))) {
                fprintf(stderr, "failed to capture packet on interface %s: %s\n",
                    s_tip_conf.net_if.client.name, lune_get_err_str(err));
                exit(EXIT_FAILURE);
            }
        }
#endif
    }
}

static void tip_disable_client_net_if(void)
{
    int err;

    if (0 != (err = lune_disable_net_if(s_tip_client_net_if_id))) {
        fprintf(stderr, "failed to disable interface %d: %s\n",
            s_tip_client_net_if_id, lune_get_err_str(err));
        exit(EXIT_FAILURE);
    }
}

static void tip_connect_net_if(void)
{
    int err;

    if ((LUNE_NET_IF_VIRT == s_tip_conf.net_if.client.type
        && LUNE_NET_IF_VIRT != s_tip_conf.net_if.server.type)
        || (LUNE_NET_IF_VIRT != s_tip_conf.net_if.client.type
        && LUNE_NET_IF_VIRT == s_tip_conf.net_if.server.type)) {
        fprintf(stderr, "failed to connect interface %s and %s: %s\n",
            s_tip_conf.net_if.client.name,
            s_tip_conf.net_if.server.name,
            lune_get_err_str(lune_set_err_no(LUNE_ERR_NET_IF_TYPE_ERR)));
        exit(EXIT_FAILURE);
    }

    if (LUNE_NET_IF_VIRT == s_tip_conf.net_if.client.type) {
        if (0 != (err = lune_connect_net_if(s_tip_client_net_if_id, s_tip_server_net_if_id))) {
        fprintf(stderr, "failed to connect interface %s and %s: %s\n",
            s_tip_conf.net_if.client.name,
            s_tip_conf.net_if.server.name,
            lune_get_err_str(err));
            exit(EXIT_FAILURE);
        }
    }
}

static void tip_disconnect_net_if(void)
{
    int err;

    if (LUNE_NET_IF_VIRT == s_tip_conf.net_if.client.type) {
        if (0 != (err = lune_disconnect_net_if(s_tip_client_net_if_id))) {
        fprintf(stderr, "failed to disconnect interface %s and %s: %s\n",
            s_tip_conf.net_if.client.name,
            s_tip_conf.net_if.server.name,
            lune_get_err_str(err));
            exit(EXIT_FAILURE);
        }
    }
}

void run_tip(void)
{
    int err;
    lune_conf_t conf;

    conf.id = s_tip_conf.cpu.nrt;
    conf.log_file = "./tip.log";
    conf.log_level = LUNE_VBS;
    if (0 != (err = lune_init(&conf))) {
        fprintf(stderr, "lune init failed: %s\n", lune_get_err_str(err));
        exit(EXIT_FAILURE);
    }

    s_tip_client_net_if_enable_flag = s_tip_server_net_if_enable_flag = 0;
    s_tip_start_flag = s_tip_stop_flag = 0;

    tip_create_server_net_if();

    tip_create_client_net_if();

    tip_connect_net_if();

    tip_enable_server_net_if();

    tip_enable_client_net_if();

    sleep(TIP_PRE_RUN_TIME_IN_SEC);

    /* test start */
    s_tip_start_flag = 1;

    sleep(s_tip_conf.load.time);

    /* test stop */
    s_tip_stop_flag = 1;
    s_tip_start_flag = 0;

    sleep(TIP_POST_RUN_TIME_IN_SEC);

    tip_disable_client_net_if();

    tip_disable_server_net_if();

    tip_disconnect_net_if();

    tip_delete_client_net_if();

    tip_delete_server_net_if();

    lune_fini();
}
