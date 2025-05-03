/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2024 Lune Reseau, Inc.
 */

#ifndef __LUNE_CORE_H__
#define __LUNE_CORE_H__

#include "lune/common.h"
#include "lune/log.h"
#include "lune/os/linux.h"
#include "lune/sched.h"

#ifdef __cplusplus
extern "C" {
#endif

#define LUNE_MIN_CORE_NUM_IN_BIT    (1)
#define LUNE_MIN_CORE_NUM           (1 << LUNE_MIN_CORE_NUM_IN_BIT)
#define LUNE_MAX_CORE_NUM_IN_BIT    (6)
#define LUNE_MAX_CORE_NUM           (1 << LUNE_MAX_CORE_NUM_IN_BIT)

typedef enum _lune_core_type {
    LUNE_CORE_NA = 0,               /* network aggregator */
    LUNE_CORE_NP,                   /* network processor */
    LUNE_CORE_CP,                   /* coprocessor */
    LUNE_CORE_NONE,                 /* unused */
} lune_core_type_en;

typedef enum _lune_core_opt {
    /* get options */
    LUNE_CORE_OPT_GET_TYPE,
    /* set options */
    LUNE_CORE_OPT_BIND_CP = 256,
    LUNE_CORE_OPT_UNBIND_CP,
    LUNE_CORE_OPT_UNBIND_ALL_CPS,
    LUNE_CORE_OPT_SET_LOG_CPU_USAGE_OFF,
    LUNE_CORE_OPT_SET_LOG_CPU_USAGE_ON,
} lune_core_opt_en;

typedef int (*lune_core_task_init_callback_func_t)(void *);
typedef void (*lune_core_task_fini_callback_func_t)(void);

typedef struct _lune_core_task {
    lune_core_task_init_callback_func_t init;
    lune_core_task_fini_callback_func_t fini;
    char name[LUNE_MAX_SHORT_NAME_BUF_LEN];
    void *data;
} lune_core_task_t;

typedef struct _lune_core_conf {
    unsigned int id;                /* RT core id */
    lune_core_type_en type;
    unsigned int hz;
    lune_log_level_en log_level;
    char log_file[LUNE_MAX_NAME_BUF_LEN];
    lune_core_task_t task;
} lune_core_conf_t;

/*
    IMPORTANT:
    1. It's highly recommended that cores used by lune are isolated by boot option
       "isolcpus" so that they don't get swapped out via kernel preemption.
    2. All the core APIs running on non-realtime cores are NOT thread-safe. They
       MUST all be called in one thread.
*/

int lune_create_core(lune_core_conf_t *conf);
int lune_delete_core(unsigned int id);

int lune_is_core_running(unsigned int id);

int lune_get_core_opt(unsigned int id,
    lune_core_opt_en opt, unsigned char *opt_val, unsigned int opt_len);
int lune_set_core_opt(unsigned int id,
    lune_core_opt_en opt, const unsigned char *opt_val, unsigned int opt_len);

/*
    the pair is used for LUNE_COMM_REQ_APP only and has to be called in pair
    by firstly send a request to core and then wait to receive response from core

    for lune_recv_resp_from_core():
    1. if pbuf is NULL, retrieve the error code only, any present response will be
       discarded.
    2. plen MUST NOT be NULL. returned response may be truncated if *plen is less
       than the actual length of original response and *plen will return the actual
       length.
    3. perr MUST NOT be NULL. it returns error occurred on core.
*/
int lune_send_req_to_core(unsigned int id, const unsigned char *buf, unsigned int len);
int lune_recv_resp_from_core(unsigned int id, unsigned char *pbuf, unsigned int *plen, int *perr);

/* the following APIs are called on core only */
int lune_core_get_opt(lune_core_opt_en opt, unsigned char *opt_val, unsigned int opt_len);
int lune_core_set_opt(lune_core_opt_en opt, const unsigned char *opt_val, unsigned int opt_len);

int lune_core_send_resp(const unsigned char *buf, unsigned int len, int err);
int lune_core_get_id(void);

#ifdef __cplusplus
}
#endif

#endif