/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2024 Lune Reseau, Inc.
 */

#ifndef __SCHED_H__
#define __SCHED_H__

#include "lune/sched.h"

#include "kernel/time.h"

/* best-effort threshold */
#define SCHED_CPU_USAGE_TH_BE                   (0.80)
/* overall threshold */
#define SCHED_CPU_USAGE_TH_OA                   (0.85)

#define SCHED_CHECK_POINT()                     \
    {                                           \
        if (g_sched_schedulable_flag) {         \
            g_sched_be_check_last_tick = g_sched_be_check_curr_tick;                \
            TIME_GET_CLK_TICK(&g_sched_be_check_curr_tick);                         \
            if (TIME_AFTER(g_sched_be_check_curr_tick + g_sched_tick_shift, \
                g_sched_be_expected_end)) {     \
                g_sched_schedulable_flag = 0;   \
                sched_swap_task();              \
            }                                   \
        }                                       \
    }

#define sched_add_task(name, func, data, prio)  \
    __sched_add_task(#func, name, ((lune_task_func_t)(func)), data, prio, 1)

extern __thread int g_sched_schedulable_flag;
extern __thread time_tick_t g_sched_be_expected_end;
extern __thread time_tick_t g_sched_be_check_last_tick;
extern __thread time_tick_t g_sched_be_check_curr_tick;
extern __thread long long g_sched_tick_shift;

typedef enum _sched_prio {
    /*
        Normal tasks are guaranteed to be called in every cycle.
    */
    SCHED_PRIO_NORMAL = 0,
    /*
        Best-effort tasks are not guaranteed to be called in every cycle.
        period. They may be skipped in case cpu usage reach or go beyond
        threshold.
    */
    SCHED_PRIO_BEST_EFFORT,
    /*
        NOTICE: the following priorities are only used internally
    */
    /*
        Receiving tasks are called multiple times in a cycle in order to
        process packets and respond ASAP.
    */
    SCHED_PRIO_RECV,
    /*
        Timer task (one and only one) is called at the beginning of every
        cycle.
    */
    SCHED_PRIO_TIMER,
    /*
        Sending tasks are guaranteed to be called in every cycle for transmitting
        packets aggregated in the current cycle.
    */
    SCHED_PRIO_SEND,
    SCHED_PRIO_MAX,
} sched_prio_en;

int sched_local_init(void);

void sched_local_fini(void);

void sched_swap_task(void);

unsigned int __sched_add_task(const char *prefix,
    const char *name,
    lune_task_func_t func,
    void *data,
    sched_prio_en prio,
    unsigned int is_kern);

int sched_del_task(unsigned int task_id);

void sched_loop(void);
void sched_mini_loop(void);

#endif