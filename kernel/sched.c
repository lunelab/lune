/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2024 Lune Reseau, Inc.
 */

#include "lune/assert.h"
#include "lune/id.h"
#include "lune/list.h"
#include "lune/log.h"
#include "lune/os/linux.h"

#include "drv/net_if.h"
#include "err/err.h"
#include "kernel/sched.h"
#include "kernel/time.h"
#include "lib/common.h"
#include "log/log.h"
#include "mem/mem.h"
#include "rt/core.h"

/* threshold of cpu overload count per second for logging */
#define SCHED_CPU_OL_CNT_PER_SEC_LOG_TH ((unsigned int)(TIME_HZ * 0.6))

/* threshold of cpu overload for logging (without compression) */
#define SCHED_CPU_OL_LOG_TH             (1.1)

typedef struct _sched_prio_list {
    dlist_head_t head;
    unsigned int cnt;
} sched_prio_list_t;

/* best-effort task */
typedef struct _sched_be_task {
#define SCHED_BE_TASK_CTXT_STACK_SIZE   (1024 * 256)
    char *csp;
    ucontext_t ctxt;
} sched_be_task_t;

typedef struct _sched_task {
    dlist_node_t node;
    char name[LUNE_MAX_LONG_NAME_BUF_LEN];
    lune_task_func_t func;
    void *data;
    sched_prio_en prio;
#define SCHED_FLAG_ON(t, flag)          (((sched_task_t *)(t))->flags & (flag))
#define SCHED_SET_FLAG(t, flag)         \
    do { ((sched_task_t *)(t))->flags |= (flag); } while (0)
#define SCHED_CLEAR_FLAG(t, flag)       \
    do { ((sched_task_t *)(t))->flags &= (~flag); } while (0)
#define SCHED_FLAG_RUNNING_DELETED      0x00000001
#define SCHED_IS_RUNNING_DELETED(t)     SCHED_FLAG_ON(t, SCHED_FLAG_RUNNING_DELETED)
#define SCHED_SET_RUNNING_DELETED(t)    SCHED_SET_FLAG(t, SCHED_FLAG_RUNNING_DELETED)
#define SCHED_CLEAR_RUNNING_DELETED(t)  SCHED_CLEAR_FLAG(t, SCHED_FLAG_RUNNING_DELETED)
#define SCHED_FLAG_KERNEL_TASK          0x00000002
#define SCHED_IS_KERNEL_TASK(t)         SCHED_FLAG_ON(t, SCHED_FLAG_KERNEL_TASK)
#define SCHED_SET_KERNEL_TASK(t)        SCHED_SET_FLAG(t, SCHED_FLAG_KERNEL_TASK)
#define SCHED_CLEAR_KERNEL_TASK(t)      SCHED_CLEAR_FLAG(t, SCHED_FLAG_KERNEL_TASK)
    unsigned int flags;
    union {
        sched_be_task_t be;
    };
} sched_task_t;

static __thread sched_prio_list_t s_sched_prio_list_array[SCHED_PRIO_MAX] = {{{0},0}};

static __thread unsigned int s_sched_curr_task_id;
static __thread void *s_sched_task_set = NULL;

static __thread int s_sched_exit_flag;
__thread int g_sched_schedulable_flag;

static __thread time_tick_t s_sched_cycle_start, s_sched_cycle_expected_end;
#ifdef LUNE_DEBUG
static __thread time_tick_t s_sched_curr_task_start;
static __thread time_tick_t s_sched_curr_task_end;
static __thread time_tick_t s_sched_last_task_start;
static __thread time_tick_t s_sched_last_task_end;
#endif

static __thread unsigned int s_sched_hz_tick;
static __thread ucontext_t s_sched_be_loop_ctxt;
__thread time_tick_t g_sched_be_expected_end;
__thread time_tick_t g_sched_be_check_last_tick;
__thread time_tick_t g_sched_be_check_curr_tick;
__thread long long g_sched_tick_shift;

static void sched_init_task(void *p)
{
    sched_task_t *t = (sched_task_t *)p;

    dlist_init_node(&t->node);
    t->func = NULL;
    t->data = NULL;
    t->prio = SCHED_PRIO_MAX;
    t->flags = 0;
}

static void sched_free_task(void *p __attribute__((unused)))
{
    /* tasks should all have been deleted before */
    lune_assert(0);
}

int sched_local_init(void)
{
    int i;

    if (NULL == (s_sched_task_set = mem_create_s_array("task",
        sizeof(sched_task_t), LUNE_MAX_TASK_NUM, sched_init_task))) {
        return ERR_GET_LAST_ERR();
    }

    for (i = 0; i < SCHED_PRIO_MAX; i++) {
        dlist_init_head(&s_sched_prio_list_array[i].head);
        s_sched_prio_list_array[i].cnt = 0;
    }

    s_sched_curr_task_id = LUNE_INVALID_ID;
    s_sched_exit_flag = g_sched_schedulable_flag = 0;

    return 0;
}

void sched_local_fini(void)
{
    sched_task_t *t, *t2;
    int i;

    s_sched_curr_task_id = LUNE_INVALID_ID;
    s_sched_exit_flag = g_sched_schedulable_flag = 0;

    for (i = 0; i < SCHED_PRIO_MAX; i++) {
        dlist_for_each_node_safe(t, t2, &s_sched_prio_list_array[i].head, node) {
            dlist_del(&t->node);
            mem_s_array_free(s_sched_task_set, t);
        }

        s_sched_prio_list_array[i].cnt = 0;
    }

    mem_delete_s_array(s_sched_task_set, sched_free_task);
}

/*
    when lune_exit() is called, sched_loop() will not exit right away but 
    wait until current cycle finishes.
*/
void lune_exit(void)
{
    if (0 != s_sched_exit_flag) {
        lune_log(LUNE_WARN, "lune_exit() has already been called on %s",
            CORE_GET_NAME());
        return;
    }

    s_sched_exit_flag = 1;
}

void sched_swap_task(void)
{
    sched_task_t *t;

    t = (sched_task_t *)MEM_STATIC_ARRAY_LIST_GET_MEM(s_sched_task_set, s_sched_curr_task_id);
    swapcontext(&t->be.ctxt, &s_sched_be_loop_ctxt);
}

static void sched_be_task_helper(sched_task_t *t)
{
    t->func(t->data);
    /* task has to be re-initialized for recurrence */
    makecontext(&t->be.ctxt, (void (*)(void))sched_be_task_helper, 1, t);
}

unsigned int __sched_add_task(const char *prefix,
    const char *name,
    lune_task_func_t func,
    void *data,
    sched_prio_en prio,
    unsigned int is_kern)
{
    sched_task_t *t;

    if (NULL == name || NULL == func || prio < SCHED_PRIO_NORMAL || prio >= SCHED_PRIO_MAX) {
        ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        goto ERR_1;
    }

    if (NULL == (t = mem_s_array_alloc(s_sched_task_set))) {
        goto ERR_1;
    }

    /* there must be only one timer task per core */
    if (SCHED_PRIO_TIMER == prio && 1 == s_sched_prio_list_array[prio].cnt) {
        ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        goto ERR_2;
    }

    sprintf(t->name, "%s:%s", prefix, name);
    lune_str_replace_char(t->name, ' ', '_');
    t->func = func;
    t->data = data;
    t->prio = prio;
    t->flags = 0;
    if (is_kern) {
        SCHED_SET_KERNEL_TASK(t);
    }
    if (SCHED_PRIO_BEST_EFFORT == prio) {
        if (NULL == (t->be.csp = lune_malloc(SCHED_BE_TASK_CTXT_STACK_SIZE))) {
            goto ERR_2;
        }
        getcontext(&t->be.ctxt);
        t->be.ctxt.uc_link = &s_sched_be_loop_ctxt;
        t->be.ctxt.uc_stack.ss_sp = t->be.csp;
        t->be.ctxt.uc_stack.ss_size = SCHED_BE_TASK_CTXT_STACK_SIZE;
        makecontext(&t->be.ctxt, (void (*)(void))sched_be_task_helper, 1, t);
    }
    dlist_add_tail(&t->node, &s_sched_prio_list_array[prio].head);
    s_sched_prio_list_array[prio].cnt++;

    return MEM_STATIC_ARRAY_LIST_GET_IDX(s_sched_task_set, t);

ERR_2:
    mem_s_array_free(s_sched_task_set, t);

ERR_1:
    return LUNE_INVALID_ID;
}

static void __sched_del_task(sched_task_t *t)
{
    dlist_del_init(&t->node);
    s_sched_prio_list_array[t->prio].cnt--;
    if (SCHED_PRIO_BEST_EFFORT == t->prio) {
        lune_free(t->be.csp);
    }
    mem_s_array_free(s_sched_task_set, t);
}

int sched_del_task(unsigned int task_id)
{
    sched_task_t *t;

    lune_assert(task_id < LUNE_MAX_TASK_NUM);

    t = (sched_task_t *)MEM_STATIC_ARRAY_LIST_GET_MEM(s_sched_task_set, task_id);

    lune_assert(SCHED_IS_KERNEL_TASK(t));
    lune_assert(dlist_node_is_added(&t->node));
    lune_assert(task_id != s_sched_curr_task_id);

    __sched_del_task(t);
    return 0;
}

#ifdef LUNE_DEBUG
static inline void sched_perf_mon_container_run(sched_task_t *t,
    time_tick_t tick_cycle_start, time_tick_t tick_cycle_expected_end)
{
    float total_cpu_usage, task_cpu_usage;

    s_sched_last_task_start = s_sched_curr_task_start;
    s_sched_last_task_end = s_sched_curr_task_end;
    TIME_GET_CLK_TICK(&s_sched_curr_task_start);
    if (SCHED_PRIO_BEST_EFFORT == t->prio) {
        swapcontext(&s_sched_be_loop_ctxt, &t->be.ctxt);
    } else {
        t->func(t->data);
    }
    TIME_GET_CLK_TICK(&s_sched_curr_task_end);
    if (TIME_AFTER(s_sched_curr_task_end, tick_cycle_expected_end)) {
        total_cpu_usage = TIME_GET_CPU_USAGE_PER_CYCLE(tick_cycle_start,
            s_sched_curr_task_end);
        task_cpu_usage = TIME_GET_CPU_USAGE_PER_CYCLE(s_sched_curr_task_start,
            s_sched_curr_task_end);
        if (LOG_IS_CPU_USAGE_ON()) {
            lune_log(LUNE_WARN, "task: %s, task usage: %.2f%%, "
                "cpu usage: %.2f%% at %.4fs with tick shift %lld",
                t->name,
                task_cpu_usage * 100,
                total_cpu_usage * 100,
                (float)s_sched_hz_tick / LUNE_TIME_GET_HZ(),
                g_sched_tick_shift);
        }
    }
}
#endif

void sched_loop(void)
{
    sched_task_t *t, *t2, *timer_task;
    dlist_head_t list;
    float cpu_usage_per_cycle;
    unsigned int hz = LUNE_TIME_GET_HZ(), hz_per_min_hz = hz / LUNE_MIN_HZ;
    int bbe_oth_cnt = 0;    /* counts of overthreshold before best-effort gets scheduled per ms */
    int total_ol_cnt = 0;   /* counts of cpu overload per cycle */
    int err;
    unsigned int timer_task_id;
    long long curr_cycle_tick_shift;
    time_tick_t curr_cycle_ticks, now;

    lune_assert(1 == s_sched_prio_list_array[SCHED_PRIO_TIMER].cnt);
    timer_task = dlist_first(&s_sched_prio_list_array[SCHED_PRIO_TIMER].head, sched_task_t, node);
    timer_task_id = MEM_STATIC_ARRAY_LIST_GET_IDX(s_sched_task_set, timer_task);
    g_sched_tick_shift = curr_cycle_tick_shift = 0;

    s_sched_hz_tick = 0;

    TIME_GET_CLK_TICK(&s_sched_cycle_start);
    while (1) {
        g_sched_be_expected_end = TIME_GET_TH_BE_TICKS(s_sched_cycle_start);
        s_sched_cycle_expected_end = TIME_GET_TH_OA_TICKS(s_sched_cycle_start);

        s_sched_hz_tick++;

        /* run timer task */
        s_sched_curr_task_id = timer_task_id;
#ifdef LUNE_DEBUG
        sched_perf_mon_container_run(timer_task, s_sched_cycle_start, s_sched_cycle_expected_end);
#else
        timer_task->func(timer_task->data);
#endif

        /* run receiving task(s) */
        dlist_for_each_node(t, &s_sched_prio_list_array[SCHED_PRIO_RECV].head, node) {
            s_sched_curr_task_id = MEM_STATIC_ARRAY_LIST_GET_IDX(s_sched_task_set, t);
#ifdef LUNE_DEBUG
            sched_perf_mon_container_run(t, s_sched_cycle_start, s_sched_cycle_expected_end);
#else
            t->func(t->data);
#endif
        }

        /* run normal task(s) */
        dlist_for_each_node(t, &s_sched_prio_list_array[SCHED_PRIO_NORMAL].head, node) {
            s_sched_curr_task_id = MEM_STATIC_ARRAY_LIST_GET_IDX(s_sched_task_set, t);
#ifdef LUNE_DEBUG
            sched_perf_mon_container_run(t, s_sched_cycle_start, s_sched_cycle_expected_end);
#else
            t->func(t->data);
#endif
            if (unlikely(SCHED_IS_RUNNING_DELETED(t))) {
                lune_assert(!SCHED_IS_KERNEL_TASK(t));
                /* dlist_for_each_node_safe not used here for performance's sake */
                t2 = t;
                t = dlist_prev(t, node);
                __sched_del_task(t2);
            }
        }

        /* run sending task(s) */
        dlist_for_each_node(t, &s_sched_prio_list_array[SCHED_PRIO_SEND].head, node) {
            s_sched_curr_task_id = MEM_STATIC_ARRAY_LIST_GET_IDX(s_sched_task_set, t);

#ifdef LUNE_DEBUG
            sched_perf_mon_container_run(t, s_sched_cycle_start, s_sched_cycle_expected_end);
#else
            t->func(t->data);
#endif
        }

        TIME_GET_CLK_TICK(&now);
        if (TIME_AFTER(now + g_sched_tick_shift, s_sched_cycle_expected_end)) {
            cpu_usage_per_cycle = TIME_GET_CPU_USAGE_PER_CYCLE(s_sched_cycle_start, now);
            if (cpu_usage_per_cycle >= 1
                && LOG_IS_CPU_USAGE_ON()) {
                lune_log(LUNE_WARN, "cpu usage has reached %.2f%% after "
                    "SCHED_PRIO_SEND tasks run on %s at %.4fs with tick shift %lld",
                    cpu_usage_per_cycle * 100,
                    CORE_GET_NAME(),
                    (float)s_sched_hz_tick / LUNE_TIME_GET_HZ(),
                    g_sched_tick_shift);
            }

            if ((++bbe_oth_cnt % hz_per_min_hz) != 0) {
                /* skip all remaining tasks for current cycle */
                goto SLEEP_TILL_NEXT_CYCLE;
            }

            /*
                run one best-effort task despite of overloaded cpu in last 1ms
            */
            lune_log_once(LUNE_WARN, "SCHED_PRIO_BEST_EFFORT task running with "
                "cpu overloaded on %s at %.4fs with tick shift %lld",
                CORE_GET_NAME(),
                (float)s_sched_hz_tick / LUNE_TIME_GET_HZ(),
                g_sched_tick_shift);
        } else if (TIME_AFTER(now + g_sched_tick_shift, g_sched_be_expected_end)) {
            if ((++bbe_oth_cnt % hz_per_min_hz) != 0) {
                /* skip best-effort tasks for current cycle */
                goto BEST_EFFORT_DONE;
            }
        } else {
            bbe_oth_cnt = 0;
        }

        /* run best-effort task(s) */
        g_sched_schedulable_flag = 1;
        dlist_init_head(&list);
        dlist_for_each_node_safe(t, t2, &s_sched_prio_list_array[SCHED_PRIO_BEST_EFFORT].head, node) {
            s_sched_curr_task_id = MEM_STATIC_ARRAY_LIST_GET_IDX(s_sched_task_set, t);

#ifdef LUNE_DEBUG
            sched_perf_mon_container_run(t, s_sched_cycle_start, s_sched_cycle_expected_end);
            now = s_sched_curr_task_end;
#else
            swapcontext(&s_sched_be_loop_ctxt, &t->be.ctxt);
            TIME_GET_CLK_TICK(&now);
#endif
            if (TIME_AFTER(now + g_sched_tick_shift, s_sched_cycle_expected_end)) {
                cpu_usage_per_cycle = TIME_GET_CPU_USAGE_PER_CYCLE(s_sched_cycle_start, now);
                if (cpu_usage_per_cycle >= 1
                    && LOG_IS_CPU_USAGE_ON()) {
                    lune_log(LUNE_WARN, "cpu usage has reached %.2f%% after "
                        "SCHED_PRIO_BEST_EFFORT tasks run on %s at %.4fs with tick shift %lld",
                        cpu_usage_per_cycle * 100,
                        CORE_GET_NAME(),
                        (float)s_sched_hz_tick / LUNE_TIME_GET_HZ(),
                        g_sched_tick_shift);
                }

                dlist_del(&t->node);
                dlist_add_tail(&t->node, &list);
                dlist_move_list_tail(&list, &s_sched_prio_list_array[SCHED_PRIO_BEST_EFFORT].head);
                if (g_sched_schedulable_flag) {
                    if (unlikely(SCHED_IS_RUNNING_DELETED(t))) {
                        lune_assert(!SCHED_IS_KERNEL_TASK(t));
                        __sched_del_task(t);
                    }
                    g_sched_schedulable_flag = 0;
                }
                goto SLEEP_TILL_NEXT_CYCLE;
            }

            if (TIME_AFTER(now + g_sched_tick_shift, g_sched_be_expected_end)) {
                dlist_del(&t->node);
                dlist_add_tail(&t->node, &list);
                dlist_move_list_tail(&list, &s_sched_prio_list_array[SCHED_PRIO_BEST_EFFORT].head);
                if (g_sched_schedulable_flag) {
                    if (unlikely(SCHED_IS_RUNNING_DELETED(t))) {
                        lune_assert(!SCHED_IS_KERNEL_TASK(t));
                        __sched_del_task(t);
                    }
                    g_sched_schedulable_flag = 0;
                }
                goto BEST_EFFORT_DONE;
            }

            lune_assert(g_sched_schedulable_flag);

            if (&t2->node != &s_sched_prio_list_array[SCHED_PRIO_BEST_EFFORT].head
                && !dlist_node_is_added(&t2->node)) {
                /* t2 was deleted while t running */
                t2 = dlist_next(t, node);
            }

            dlist_del(&t->node);
            dlist_add_tail(&t->node, &list);

            if (unlikely(SCHED_IS_RUNNING_DELETED(t))) {
                lune_assert(!SCHED_IS_KERNEL_TASK(t));
                __sched_del_task(t);
            }
        }

        dlist_move_list_tail(&list, &s_sched_prio_list_array[SCHED_PRIO_BEST_EFFORT].head);
        g_sched_schedulable_flag = 0;

BEST_EFFORT_DONE:
        if (0 == s_sched_prio_list_array[SCHED_PRIO_RECV].cnt) {
            goto SLEEP_TILL_NEXT_CYCLE;
        }

        /* loop receiving task(s) till cpu threshold */
        while (1) {
            dlist_init_head(&list);
            dlist_for_each_node_safe(t, t2, &s_sched_prio_list_array[SCHED_PRIO_RECV].head, node) {
                dlist_del(&t->node);
                dlist_add_tail(&t->node, &list);

                s_sched_curr_task_id = MEM_STATIC_ARRAY_LIST_GET_IDX(s_sched_task_set, t);

#ifdef LUNE_DEBUG
                sched_perf_mon_container_run(t, s_sched_cycle_start,
                    s_sched_cycle_start + TIME_GET_TICKS_PER_CYCLE());
                now = s_sched_curr_task_end;
#else
                t->func(t->data);
                TIME_GET_CLK_TICK(&now);
#endif
                if (TIME_AFTER(now + g_sched_tick_shift, s_sched_cycle_expected_end)) {
                    cpu_usage_per_cycle = TIME_GET_CPU_USAGE_PER_CYCLE(s_sched_cycle_start, now);
                    if (cpu_usage_per_cycle >= 1
                        && !CORE_IS_NA()
                        && LOG_IS_CPU_USAGE_ON()) {
                        if (cpu_usage_per_cycle > SCHED_CPU_OL_LOG_TH) {
                            lune_log(LUNE_WARN, "cpu usage has reached %.2f%% after SCHED_PRIO_RECV "
                                "tasks run in idle on %s at %.4fs with tick shift %lld",
                                cpu_usage_per_cycle * 100,
                                CORE_GET_NAME(),
                                (float)s_sched_hz_tick / LUNE_TIME_GET_HZ(),
                                g_sched_tick_shift);
                        } else {
                            lune_log_once(LUNE_WARN, "cpu usage has reached %.2f%% after SCHED_PRIO_RECV "
                                "tasks run in idle on %s at %.4fs with tick shift %lld",
                                cpu_usage_per_cycle * 100,
                                CORE_GET_NAME(),
                                (float)s_sched_hz_tick / LUNE_TIME_GET_HZ(),
                                g_sched_tick_shift);
                        }
                    }

                    dlist_move_list_tail(&list, &s_sched_prio_list_array[SCHED_PRIO_RECV].head);
                    goto SLEEP_TILL_NEXT_CYCLE;
                }
            }

            dlist_move_list_tail(&list, &s_sched_prio_list_array[SCHED_PRIO_RECV].head);
        }

SLEEP_TILL_NEXT_CYCLE:
        if (CORE_IS_EXIT_REQUIRED() || s_sched_exit_flag) {
            goto EXIT;
        }

        hz--;
        if (0 == (hz % hz_per_min_hz)) {
            /* last cycle of the period of minimum hz, which is 1 millisecond */
            if (CORE_RELOAD_IS_NEEDED()) {
                /* configuration modified, reload is required */
                if (0 != (err = core_reload_conf())) {
                    lune_log(LUNE_INFO, "failed to reload configuration on %s",
                        CORE_GET_NAME());
                    /* keep going regardless */
                }
            }

            if (0 == hz) {
                lune_assert(g_sched_tick_shift >= 0);
                if (g_sched_tick_shift >= (long long)TIME_GET_TICKS_PER_MIN_HZ()) {
                    lune_log(LUNE_WARN, "time shift at second %d: %.4f%%",
                        s_sched_hz_tick / LUNE_TIME_GET_HZ(),
                        (float)g_sched_tick_shift * 100 / TIME_GET_TICKS_PER_SEC());
                }

                hz = LUNE_TIME_GET_HZ();

                if ((unsigned int)total_ol_cnt >= SCHED_CPU_OL_CNT_PER_SEC_LOG_TH) {
                    lune_log(LUNE_INFO, "cpu overload counts hit %d in last second on %s",
                        total_ol_cnt, CORE_GET_NAME());
                }

                total_ol_cnt = 0;
                curr_cycle_ticks = TIME_GET_TICKS_LAST_CYCLE_OF_SEC();
            } else {
                curr_cycle_ticks = TIME_GET_TICKS_LAST_CYCLE_OF_MIN_HZ();
            }
        } else {
            curr_cycle_ticks = TIME_GET_TICKS_PER_CYCLE();
        }

        TIME_GET_CLK_TICK(&now);
        curr_cycle_tick_shift = TIME_GET_TICKS_DELTA(now, s_sched_cycle_start + curr_cycle_ticks);
        if (g_sched_tick_shift + curr_cycle_tick_shift >= 0) {
            g_sched_tick_shift += curr_cycle_tick_shift;
            total_ol_cnt++;
            TIME_GET_CLK_TICK(&s_sched_cycle_start);
            continue;
        }

        TIME_SHIFT_DELTA(s_sched_cycle_start, -g_sched_tick_shift);
        g_sched_tick_shift = 0;

        s_sched_cycle_start = time_sleep_till_next_cycle(s_sched_cycle_start, curr_cycle_ticks);
    }

EXIT:
    s_sched_curr_task_id = LUNE_INVALID_ID;

    lune_assert(CORE_IS_RUNNING());
    CORE_SET_QUITTING();

    if (unlikely(0 != (err = core_cleanup_core()))) {
        lune_log(LUNE_INFO, "failed to clean up core while exiting on %s: %s",
            CORE_GET_NAME(), ERR_GET_ERR_STR(err));
    }
}

void sched_mini_loop(void)
{
    sched_task_t *t, *t2;
    int err;

    lune_assert(0 == s_sched_prio_list_array[SCHED_PRIO_RECV].cnt);
    lune_assert(0 == s_sched_prio_list_array[SCHED_PRIO_SEND].cnt);

    while (1) {
        /* run normal task(s) */
        dlist_for_each_node(t, &s_sched_prio_list_array[SCHED_PRIO_NORMAL].head, node) {
            s_sched_curr_task_id = MEM_STATIC_ARRAY_LIST_GET_IDX(s_sched_task_set, t);
            t->func(t->data);
            if (unlikely(SCHED_IS_RUNNING_DELETED(t))) {
                lune_assert(!SCHED_IS_KERNEL_TASK(t));
                /* dlist_for_each_node_safe not used here for performance's sake */
                t2 = t;
                t = dlist_prev(t, node);
                __sched_del_task(t2);
            }
        }

        if (CORE_IS_EXIT_REQUIRED() || s_sched_exit_flag) {
            goto EXIT;
        }
    }

EXIT:
    s_sched_curr_task_id = LUNE_INVALID_ID;

    lune_assert(CORE_IS_RUNNING());
    CORE_SET_QUITTING();

    if (unlikely(0 != (err = core_cleanup_core()))) {
        lune_log(LUNE_INFO, "failed to clean up core while exiting on %s: %s",
            CORE_GET_NAME(), ERR_GET_ERR_STR(err));
    }
}

unsigned int __lune_add_task(const char *prefix,
    const char *name, lune_task_func_t func, void *data, lune_task_prio_en prio)
{
    sched_prio_en sched_prio;

    if (prio < LUNE_TASK_PRIO_NORMAL || prio >= LUNE_TASK_PRIO_MAX) {
        ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        return LUNE_INVALID_ID;
    }

    if (strlen(name) > LUNE_MAX_NAME_LEN) {
        ERR_SET_ERR(LUNE_ERR_NAME_TOO_LONG);
        return LUNE_INVALID_ID;
    }

    if (LUNE_TASK_PRIO_NORMAL == prio) {
        sched_prio = SCHED_PRIO_BEST_EFFORT;
    } else {
        /* LUNE_TASK_PRIO_HIGH */
        sched_prio = SCHED_PRIO_NORMAL;
    }

    return __sched_add_task(prefix, name, func, data, sched_prio, 0);
}

int lune_del_task(unsigned int task_id)
{
    sched_task_t *t;

    if (task_id >= LUNE_MAX_TASK_NUM) {
        return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
    }

    t = (sched_task_t *)MEM_STATIC_ARRAY_LIST_GET_MEM(s_sched_task_set, task_id);
    if (unlikely(!dlist_node_is_added(&t->node))) {
        return ERR_SET_ERR(LUNE_ERR_ID_NOT_FOUND);
    }

    if (SCHED_IS_KERNEL_TASK(t)) {
        return ERR_SET_ERR(LUNE_ERR_PERM_DENIED);
    }

    if (task_id == s_sched_curr_task_id) {
        if (unlikely(SCHED_PRIO_NORMAL != t->prio
            && SCHED_PRIO_BEST_EFFORT != t->prio)) {
            /* further investigation needed once reach here */
            return ERR_SET_ERR(LUNE_ERR_NOT_SUPPORTED);
        }

        /* application task deletes itself */
        SCHED_SET_RUNNING_DELETED(t);
        return 0;
    }

    __sched_del_task(t);
    return 0;
}

int lune_yield(void)
{
    if (!g_sched_schedulable_flag) {
        return ERR_SET_ERR(LUNE_ERR_NOT_SUPPORTED);
    }

    sched_swap_task();
    return 0;
}

unsigned int lune_get_curr_task_id(void)
{
    return s_sched_curr_task_id;
}
