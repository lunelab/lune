/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2024 Lune Reseau, Inc.
 */

#ifndef __LUNE_SCHED_H__
#define __LUNE_SCHED_H__

#ifdef __cplusplus
extern "C" {
#endif

#define LUNE_MAX_TASK_NUM                       (128)

#define lune_add_task(name, func, data, prio)   \
    __lune_add_task(#func, name, func, data, prio)

typedef enum _lune_task_prio {
    /*
        Normal-priority tasks are not guaranteed to be called in every cycle.
        It may be skipped for some cycles where cpu is overloaded.

        IMPORTANT:
        Total stack size for a normal task is 256K. The task itself MUST NOT
        allocate large buffer on stack, which may result in crash once the stack
        breach the limit.
    */
    LUNE_TASK_PRIO_NORMAL,
    /*
        High-priority tasks are called in every cycle. Caller must guarantee
        tasks of this type not to take too much time in every call. Failing
        to do so will cause irreversible time shift and damage time accuracy
        in lune kernel.
    */
    LUNE_TASK_PRIO_HIGH,
    LUNE_TASK_PRIO_MAX,
} lune_task_prio_en;

typedef void (*lune_task_func_t)(void *);

void lune_exit(void);

unsigned int __lune_add_task(const char *prefix,
    const char *name, lune_task_func_t func, void *data, lune_task_prio_en prio);

int lune_del_task(unsigned int task_id);

/*
    it should ONLY be called in task with LUNE_TASK_PRIO_NORMAL priority
*/
int lune_yield(void);

unsigned int lune_get_curr_task_id(void);

#ifdef __cplusplus
}
#endif

#endif