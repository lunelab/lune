/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2024 Lune Reseau, Inc.
 */

#ifndef __TIMER_H__
#define __TIMER_H__

#include "lune/list.h"
#include "lune/timer.h"

int timer_local_init(void);
void timer_local_fini(void);

extern __thread unsigned long long g_timer_current_jiffies;

#define TIMER_GET_TIMER_JIFFIES(tmr)    ((&(tmr))->jiffies)
#define TIMER_GET_CURRENT_JIFFIES()     (g_timer_current_jiffies)
#define TIMER_GET_TIME_ELAPSE(t)        ((long)(g_timer_current_jiffies - (t)))
#define TIMER_GET_TIME_EXPIRE(t)        ((long)((t) - g_timer_current_jiffies))
#define TIMER_TIME_AFTER_NOW(t)         (TIMER_GET_TIME_ELAPSE(t) < 0)
#define TIMER_TIME_AFTER_TIMER(t, tmr)  ((long)((t) - (&(tmr))->jiffies) > 0)
#define TIMER_TIME_BEFORE(t1, t2)       (((long)((unsigned long)(t2) - (unsigned long)(t1))) > 0)

void timer_init_timer(lune_timer_t *tmr, lune_timer_type_en type,
    lune_timer_res_en res, lune_timer_func_t func, void *data);
void timer_reuse_timer(lune_timer_t *tmr, lune_timer_type_en type,
    lune_timer_res_en res, lune_timer_func_t func, void *data);
void timer_add_timer(lune_timer_t *tmr, unsigned long long expires);
void timer_mod_timer(lune_timer_t *tmr, unsigned long long expires);
void timer_del_timer(lune_timer_t *tmr);

#endif