/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2024 Lune Reseau, Inc.
 */

#ifndef __LUNE_TIMER_H__
#define __LUNE_TIMER_H__

#include "lune/list.h"
#include "lune/thread.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum _lune_timer_type {
    LUNE_TIMER_ONCE = 0,
    LUNE_TIMER_RECURRING,
} lune_timer_type_en;

typedef enum _lune_timer_res {
    LUNE_TIMER_RES_DEFAULT = 0,
    LUNE_TIMER_RES_HIGH,        /* high resolution */
} lune_timer_res_en;

typedef void (*lune_timer_func_t)(void *);

typedef struct _lune_timer {
    dlist_node_t node;
    unsigned long long jiffies;
    lune_timer_func_t func;
    void *data;
    /* cnt points to cnt field in bucket where timer is added. it is used only for deletion */
    unsigned int *cnt;
    struct {
        /* expires works only for recurring timer */
#define LUNE_TIMER_EXPIRES_IN_BIT   (48)
#define LUNE_TIMER_MAX_EXPIRES      (((unsigned long long)1 << LUNE_TIMER_EXPIRES_IN_BIT) - 1)
#define LUNE_TIMER_FLAGS_IN_BIT     (16)
        unsigned long long expires:LUNE_TIMER_EXPIRES_IN_BIT;
        unsigned long long flags:LUNE_TIMER_FLAGS_IN_BIT;
    };
    lune_timer_type_en type;
    lune_timer_res_en res;
} lune_timer_t;

typedef struct _lune_nrt_timer {
    lune_timer_type_en type;
    long long expires;          /* by nano second */
    lune_timer_func_t func;
    void *data;
    lune_thread_t tid;
} lune_nrt_timer_t;

#define LUNE_TIMER_MINI_INIT(tmr)   do { dlist_init_node(&((tmr).node)); } while (0)
#define LUNE_TIMER_IS_ADDED(tmr)    (dlist_node_is_added(&((tmr).node)))

/* NOTICE: the following timer APIs should only be called within RT thread */
int lune_init_timer(lune_timer_t *tmr, lune_timer_type_en type,
    lune_timer_res_en res, lune_timer_func_t func, void *data);

int lune_reuse_timer(lune_timer_t *tmr, lune_timer_type_en type,
    lune_timer_res_en res, lune_timer_func_t func, void *data);

int lune_add_timer(lune_timer_t *tmr, unsigned long long expires);

int lune_mod_timer(lune_timer_t *tmr, unsigned long long expires);

int lune_del_timer(lune_timer_t *tmr);

/* NOTICE: the following timer APIs should only be called within NRT thread */
int lune_add_nrt_timer(lune_nrt_timer_t *tmr, lune_timer_type_en type,
    unsigned long long expires, lune_timer_func_t func, void *data);

int lune_del_nrt_timer(lune_nrt_timer_t *tmr);

#ifdef __cplusplus
}
#endif

#endif