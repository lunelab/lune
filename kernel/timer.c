/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2024 Lune Reseau, Inc.
 */

#include "lune/assert.h"
#include "lune/cpu.h"
#include "lune/err.h"
#include "lune/id.h"
#include "lune/list.h"
#include "lune/log.h"
#include "lune/mem.h"
#include "lune/os/linux.h"
#include "lune/time.h"

#include "err/err.h"
#include "kernel/timer.h"
#include "kernel/sched.h"
#include "nrt/nrt.h"
#include "res/cpu.h"
#include "rt/core.h"

#define TIMER_INVALID_JIFFIES           ((unsigned long long)-1)
#define TIMER_1ST_HTABLE_SIZE_IN_BIT    (20)
#define TIMER_1ST_HTABLE_SIZE           (1 << TIMER_1ST_HTABLE_SIZE_IN_BIT)
#define TIMER_1ST_HTABLE_MASK           (TIMER_1ST_HTABLE_SIZE - 1)
#define TIMER_1ST_HTABLE_PERIOD         (TIMER_1ST_HTABLE_SIZE)

#define TIMER_1ST_HASH(jiffies)         ((jiffies) & TIMER_1ST_HTABLE_MASK)

#define TIMER_1ST_HTABLE_HOPPING_TIME           (TIMER_1ST_HTABLE_PERIOD / 2)
#define TIMER_1ST_HTABLE_HOPPING_JIFFIES        \
    (g_timer_current_jiffies + TIMER_1ST_HTABLE_HOPPING_TIME)

#define TIMER_2ND_HTABLE_SIZE_IN_BIT            (20)
#define TIMER_2ND_HTABLE_SIZE                   (1 << TIMER_2ND_HTABLE_SIZE_IN_BIT)
#define TIMER_2ND_HTABLE_RES_IN_BIT             (14)
#define TIMER_2ND_HTABLE_MASK                   \
    ((unsigned long long)(TIMER_2ND_HTABLE_SIZE - 1) << TIMER_2ND_HTABLE_RES_IN_BIT)
#define TIMER_2ND_HTABLE_PERIOD                 \
    ((((long long)1) << (TIMER_2ND_HTABLE_SIZE_IN_BIT + TIMER_2ND_HTABLE_RES_IN_BIT)))

#define TIMER_2ND_HTABLE_RES_MASK               \
    ((1 << (TIMER_2ND_HTABLE_RES_IN_BIT)) - 1)
#define TIMER_IS_JIFFIES_TO_FLUSH_2ND_BUCKET()                  \
    (0 == (g_timer_current_jiffies & TIMER_2ND_HTABLE_RES_MASK))
#define TIMER_1ST_HTABLE_PROCESS_2ND_BUCKET_TIMES_IN_BIT        (10)
#define TIMER_1ST_HTABLE_PROCESS_2ND_BUCKET_TIMER_PER_EACH(cnt) \
    (((cnt) >> TIMER_1ST_HTABLE_PROCESS_2ND_BUCKET_TIMES_IN_BIT) + 1)
#define TIMER_1ST_HTABLE_PROCESS_2ND_BUCKET_TIMES               \
    (1 << TIMER_1ST_HTABLE_PROCESS_2ND_BUCKET_TIMES_IN_BIT)
#define TIMER_1ST_HTABLE_PROCESS_2ND_BUCKET_MASK                \
    ((1 << (TIMER_2ND_HTABLE_RES_IN_BIT                         \
    - TIMER_1ST_HTABLE_PROCESS_2ND_BUCKET_TIMES_IN_BIT)) - 1)
#define TIMER_IS_JIFFIES_TO_PROCESS_2ND_BUCKET()                \
    (TIMER_1ST_HTABLE_PROCESS_2ND_BUCKET_MASK                   \
    == (g_timer_current_jiffies & TIMER_1ST_HTABLE_PROCESS_2ND_BUCKET_MASK))

#define TIMER_2ND_HASH(jiffies)                 \
    (((jiffies) & TIMER_2ND_HTABLE_MASK) >> TIMER_2ND_HTABLE_RES_IN_BIT)

#define TIMER_2ND_HTABLE_HOPPING_TIME           (TIMER_2ND_HTABLE_PERIOD / 2)
#define TIMER_2ND_HTABLE_HOPPING_JIFFIES        \
    (g_timer_current_jiffies + TIMER_2ND_HTABLE_HOPPING_TIME)

#define TIMER_IS_JIFFIES_IN_1ST_HTABLE(jiffies) \
    (g_timer_current_jiffies + TIMER_1ST_HTABLE_PERIOD > (jiffies))

#define TIMER_EXPIRES(tmr)                      \
    ((long)(((tmr)->jiffies) - g_timer_current_jiffies))

#define TIMER_STATUS_USER                       (0)
#define TIMER_STATUS_HOP1                       (1)
#define TIMER_STATUS_HOP2                       (2)
#define TIMER_STATUS_INIT                       (3)
#define TIMER_GET_STATUS(tmr)                   (((lune_timer_t *)tmr)->flags)
#define TIMER_SET_STATUS(tmr, status)           \
    do { ((lune_timer_t *)tmr)->flags = (status); } while (0)

#define TIMER_IS_VALID_EXPIRES(expires)         \
    ((expires) > 0 && (expires) <= LUNE_TIMER_MAX_EXPIRES)

__thread unsigned long long g_timer_current_jiffies;

static __thread unsigned int s_timer_task_id = LUNE_INVALID_ID;

typedef struct _timer_bucket {
    dlist_head_t head;
    unsigned int cnt;
} timer_bucket_t;

typedef struct _timer_1st_htable {
    timer_bucket_t *bucket;
    timer_bucket_t _2nd_bucket;
    unsigned int size;  /* size of hash table */
    unsigned int _2nd_bucket_timer_per_each;
} timer_1st_htable_t;

typedef struct _timer_2nd_htable {
    timer_bucket_t *bucket;
    unsigned int size;
} timer_2nd_htable_t;

static __thread timer_1st_htable_t s_timer_1st_htable = {0};

static __thread timer_2nd_htable_t s_timer_2nd_htable = {0};

static int timer_create_1st_htable(unsigned int size)
{
    unsigned int i;

    if (NULL == (s_timer_1st_htable.bucket = lune_malloc_x(sizeof(timer_bucket_t) * size))) {
        return ERR_GET_LAST_ERR();
    }

    s_timer_1st_htable.size = size;
    for (i = 0; i < size; i++) {
        dlist_init_head(&s_timer_1st_htable.bucket[i].head);
        s_timer_1st_htable.bucket[i].cnt = 0;
    }

    dlist_init_head(&s_timer_1st_htable._2nd_bucket.head);
    s_timer_1st_htable._2nd_bucket.cnt = 0;
    s_timer_1st_htable._2nd_bucket_timer_per_each = 0;

    return 0;
}

static int timer_create_2nd_htable(unsigned int size)
{
    unsigned int i;

    if (NULL == (s_timer_2nd_htable.bucket = lune_malloc_x(sizeof(timer_bucket_t) * size))) {
        return ERR_GET_LAST_ERR();
    }

    s_timer_2nd_htable.size = size;
    for (i = 0; i < size; i++) {
        dlist_init_head(&s_timer_2nd_htable.bucket[i].head);
        s_timer_2nd_htable.bucket[i].cnt = 0;
    }

    return 0;
}

static void timer_delete_1st_htable(void)
{
    unsigned int i;
    lune_timer_t *tmr, *tmr2;

    for (i = 0; i < s_timer_1st_htable.size; i++) {
        dlist_for_each_node_safe(tmr, tmr2, &s_timer_1st_htable.bucket[i].head, node) {
            dlist_del_init(&tmr->node);
            tmr->cnt = NULL;
        }
    }

    lune_free_x(s_timer_1st_htable.bucket);
    s_timer_1st_htable.bucket = NULL;
    s_timer_1st_htable.size = 0;

    dlist_for_each_node_safe(tmr, tmr2, &s_timer_1st_htable._2nd_bucket.head, node) {
        dlist_del_init(&tmr->node);
        tmr->cnt = NULL;
    }
    s_timer_1st_htable._2nd_bucket.cnt = 0;
    s_timer_1st_htable._2nd_bucket_timer_per_each = 0;
}

static void timer_delete_2nd_htable(void)
{
    unsigned int i;
    lune_timer_t *tmr, *tmr2;

    for (i = 0; i < s_timer_2nd_htable.size; i++) {
        dlist_for_each_node_safe(tmr, tmr2, &s_timer_2nd_htable.bucket[i].head, node) {
            dlist_del_init(&tmr->node);
            tmr->cnt = NULL;
        }
    }

    lune_free_x(s_timer_2nd_htable.bucket);
    s_timer_2nd_htable.bucket = NULL;
    s_timer_2nd_htable.size = 0;
}

void timer_init_timer(lune_timer_t *tmr, lune_timer_type_en type,
    lune_timer_res_en res, lune_timer_func_t func, void *data)
{
    dlist_init_node(&tmr->node);
    tmr->jiffies = TIMER_INVALID_JIFFIES;
    tmr->func = func;
    tmr->data = data;
    tmr->cnt = NULL;
    tmr->expires = 0;
    tmr->type = type;
    tmr->res = res;
    TIMER_SET_STATUS(tmr, TIMER_STATUS_INIT);
}

/*
    safe to use no matter whether timer is in a timer bucket or not
*/
void timer_reuse_timer(lune_timer_t *tmr, lune_timer_type_en type,
    lune_timer_res_en res, lune_timer_func_t func, void *data)
{
    lune_assert(NULL != func);

    if (TIMER_STATUS_INIT != TIMER_GET_STATUS(tmr)) {
        dlist_del_init(&tmr->node);
        *tmr->cnt -= 1;
        tmr->cnt = NULL;
    }

    tmr->jiffies = TIMER_INVALID_JIFFIES;
    tmr->func = func;
    tmr->data = data;
    tmr->expires = 0;
    tmr->type = type;
    tmr->res = res;
    TIMER_SET_STATUS(tmr, TIMER_STATUS_INIT);
}

static void timer_1st_htable_hop(lune_timer_t *tmr)
{
    long long expires;
    timer_bucket_t *tb;

    lune_assert(NULL != tmr);

    expires = TIMER_EXPIRES(tmr);
    lune_assert(expires > 0);

    if (expires < TIMER_1ST_HTABLE_PERIOD) {
        TIMER_SET_STATUS(tmr, TIMER_STATUS_USER);
        tb = &s_timer_1st_htable.bucket[TIMER_1ST_HASH(tmr->jiffies)];
    } else {
        /* keep hopping */
        lune_assert(TIMER_STATUS_HOP1 == TIMER_GET_STATUS(tmr));
        tb = &s_timer_1st_htable.bucket[TIMER_1ST_HASH(TIMER_1ST_HTABLE_HOPPING_JIFFIES)];
    }

    tmr->cnt = &tb->cnt;
    dlist_add_tail(&tmr->node, &tb->head);
    tb->cnt++;
}

static void timer_2nd_htable_hop(lune_timer_t *tmr)
{
    long long expires;
    timer_bucket_t *tb;

    lune_assert(NULL != tmr);

    expires = TIMER_EXPIRES(tmr);
    lune_assert(expires > TIMER_1ST_HTABLE_PERIOD);

    if (expires < TIMER_2ND_HTABLE_PERIOD) {
        TIMER_SET_STATUS(tmr, TIMER_STATUS_USER);
        tb = &s_timer_2nd_htable.bucket[TIMER_2ND_HASH(tmr->jiffies)];
    } else {
        /* keep hopping */
        lune_assert(TIMER_STATUS_HOP2 == TIMER_GET_STATUS(tmr));
        tb = &s_timer_2nd_htable.bucket[TIMER_2ND_HASH(TIMER_2ND_HTABLE_HOPPING_JIFFIES)];
    }

    tmr->cnt = &tb->cnt;
    dlist_add_tail(&tmr->node, &tb->head);
    tb->cnt++;
}

/*
    caller MUST ensure timer is not added to any bucket
*/
void timer_add_timer(lune_timer_t *tmr, unsigned long long expires)
{
    lune_assert(TIMER_STATUS_INIT == TIMER_GET_STATUS(tmr));

    tmr->jiffies = g_timer_current_jiffies + expires;

    if (LUNE_TIMER_RECURRING == tmr->type) {
        tmr->expires = expires;
    }

    if (expires < TIMER_1ST_HTABLE_PERIOD) {
        TIMER_SET_STATUS(tmr, TIMER_STATUS_USER);
        tmr->cnt = &s_timer_1st_htable.bucket[TIMER_1ST_HASH(tmr->jiffies)].cnt;
        dlist_add_tail(&tmr->node,
            &s_timer_1st_htable.bucket[TIMER_1ST_HASH(tmr->jiffies)].head);
        s_timer_1st_htable.bucket[TIMER_1ST_HASH(tmr->jiffies)].cnt++;
        return;
    }

    if (LUNE_TIMER_RES_HIGH == tmr->res) {
        TIMER_SET_STATUS(tmr, TIMER_STATUS_HOP1);
        tmr->cnt = &s_timer_1st_htable.bucket[TIMER_1ST_HASH(TIMER_1ST_HTABLE_HOPPING_JIFFIES)].cnt;
        dlist_add_tail(&tmr->node,
            &s_timer_1st_htable.bucket[TIMER_1ST_HASH(TIMER_1ST_HTABLE_HOPPING_JIFFIES)].head);
        s_timer_1st_htable.bucket[TIMER_1ST_HASH(TIMER_1ST_HTABLE_HOPPING_JIFFIES)].cnt++;
        return;
    }

    if (expires < TIMER_2ND_HTABLE_PERIOD) {
        TIMER_SET_STATUS(tmr, TIMER_STATUS_USER);
        tmr->cnt = &s_timer_2nd_htable.bucket[TIMER_2ND_HASH(tmr->jiffies)].cnt;
        dlist_add_tail(&tmr->node,
            &s_timer_2nd_htable.bucket[TIMER_2ND_HASH(tmr->jiffies)].head);
        s_timer_2nd_htable.bucket[TIMER_2ND_HASH(tmr->jiffies)].cnt++;
        return;
    }

    TIMER_SET_STATUS(tmr, TIMER_STATUS_HOP2);
    tmr->cnt = &s_timer_2nd_htable.bucket[TIMER_2ND_HASH(TIMER_2ND_HTABLE_HOPPING_JIFFIES)].cnt;
    dlist_add_tail(&tmr->node,
        &s_timer_2nd_htable.bucket[TIMER_2ND_HASH(TIMER_2ND_HTABLE_HOPPING_JIFFIES)].head);
    s_timer_2nd_htable.bucket[TIMER_2ND_HASH(TIMER_2ND_HTABLE_HOPPING_JIFFIES)].cnt++;
}

/*
    caller MUST ensure timer is already in a timer bucket
*/
void timer_mod_timer(lune_timer_t *tmr, unsigned long long expires)
{
    lune_assert(TIMER_STATUS_INIT != TIMER_GET_STATUS(tmr));
    dlist_del(&tmr->node);
    *tmr->cnt -= 1;
    tmr->cnt = NULL;
    TIMER_SET_STATUS(tmr, TIMER_STATUS_INIT);

    timer_add_timer(tmr, expires);
}

/*
    caller MUST ensure timer is already in a timer bucket
*/
void timer_del_timer(lune_timer_t *tmr)
{
    lune_assert(TIMER_STATUS_INIT != TIMER_GET_STATUS(tmr));
    dlist_del_init(&tmr->node);
    *tmr->cnt -= 1;
    tmr->cnt = NULL;
    TIMER_SET_STATUS(tmr, TIMER_STATUS_INIT);
}

static void timer_process_expired_timer(void *arg __attribute__((unused)))
{
    lune_timer_t *tmr;
    timer_bucket_t *tb1 = &s_timer_1st_htable.bucket[TIMER_1ST_HASH(++g_timer_current_jiffies)];

    /*
        dlist_for_each_node_safe() MUST NOT be used to loop expired timers
        cuz the cached timer(right after the one being processed) may possibly
        be deleted and cause infinite loop
    */
    while (!dlist_is_empty(&tb1->head)) {
        tmr = dlist_first(&tb1->head, lune_timer_t, node);

        dlist_del_init(&tmr->node);
        tmr->cnt = NULL;

        if (TIMER_STATUS_USER == TIMER_GET_STATUS(tmr)) {
            lune_assert(tmr->jiffies == g_timer_current_jiffies);
            TIMER_SET_STATUS(tmr, TIMER_STATUS_INIT);

            /*
                it MUST be handled prior to timer function cuz timer 
                may be freed in that function
            */
            if (LUNE_TIMER_RECURRING == tmr->type) {
                lune_assert(0 != tmr->expires);
                timer_add_timer(tmr, tmr->expires);
            }

            tmr->func(tmr->data);
        } else {
            lune_assert(TIMER_STATUS_HOP1 == TIMER_GET_STATUS(tmr));
            timer_1st_htable_hop(tmr);
        }

        tb1->cnt--;
    }

    lune_assert(0 == tb1->cnt);

    if (TIMER_IS_JIFFIES_TO_FLUSH_2ND_BUCKET()) {
        timer_bucket_t *tb2 = &s_timer_2nd_htable.bucket[TIMER_2ND_HASH(g_timer_current_jiffies)];

        lune_assert(dlist_is_empty(&s_timer_1st_htable._2nd_bucket.head));
        lune_assert(0 == s_timer_1st_htable._2nd_bucket.cnt);

        if (0 != tb2->cnt) {
            /* remove list from 2nd bucket */
            tmr = dlist_first(&tb2->head, lune_timer_t, node);
            dlist_del_init(&tb2->head);

            /* add list to 1st htable */
            dlist_add_tail(&s_timer_1st_htable._2nd_bucket.head, &tmr->node);
            s_timer_1st_htable._2nd_bucket.cnt = tb2->cnt;
            s_timer_1st_htable._2nd_bucket_timer_per_each =
                TIMER_1ST_HTABLE_PROCESS_2ND_BUCKET_TIMER_PER_EACH(s_timer_1st_htable._2nd_bucket.cnt);
            dlist_for_each_node(tmr, &s_timer_1st_htable._2nd_bucket.head, node) {
                tmr->cnt = &s_timer_1st_htable._2nd_bucket.cnt;
            }

            tb2->cnt = 0;
        }
    }

    if (TIMER_IS_JIFFIES_TO_PROCESS_2ND_BUCKET()
        && 0 != s_timer_1st_htable._2nd_bucket.cnt) {
        unsigned int i;
        unsigned int cnt =
            (s_timer_1st_htable._2nd_bucket_timer_per_each <= s_timer_1st_htable._2nd_bucket.cnt) ?   \
            s_timer_1st_htable._2nd_bucket_timer_per_each : s_timer_1st_htable._2nd_bucket.cnt;

        i = 0;
        /*
            dlist_for_each_node_safe() MUST NOT be used to loop expired timers
            cuz the cached timer(right after the one being processed) may possibly
            be deleted and cause infinite loop
        */
        while (!dlist_is_empty(&s_timer_1st_htable._2nd_bucket.head)) {
            tmr = dlist_first(&s_timer_1st_htable._2nd_bucket.head, lune_timer_t, node);

            dlist_del_init(&tmr->node);
            tmr->cnt = NULL;

            if (TIMER_STATUS_USER == TIMER_GET_STATUS(tmr)) {
                TIMER_SET_STATUS(tmr, TIMER_STATUS_INIT);

                /*
                    it MUST be handled prior to timer function cuz timer 
                    may be freed in that function
                */
                if (LUNE_TIMER_RECURRING == tmr->type) {
                    lune_assert(0 != tmr->expires);
                    timer_add_timer(tmr, tmr->expires);
                }

                tmr->func(tmr->data);
            } else {
                lune_assert(TIMER_STATUS_HOP2 == TIMER_GET_STATUS(tmr));
                timer_2nd_htable_hop(tmr);
            }

            if (++i >= cnt) {
                break;
            }
        }

        s_timer_1st_htable._2nd_bucket.cnt -= i;
    }
}

int timer_local_init(void)
{
    if (timer_create_1st_htable(TIMER_1ST_HTABLE_SIZE)) {
        goto ERR_1;
    }

    if (timer_create_2nd_htable(TIMER_2ND_HTABLE_SIZE)) {
        goto ERR_2;
    }

    if (LUNE_INVALID_ID == (s_timer_task_id = sched_add_task("timer",
        timer_process_expired_timer, NULL, SCHED_PRIO_TIMER))) {
        goto ERR_3;
    }

    g_timer_current_jiffies = (unsigned long long)-1;

    return 0;

ERR_3:
    timer_delete_2nd_htable();

ERR_2:
    timer_delete_1st_htable();

ERR_1:
    return ERR_GET_LAST_ERR();
}

void timer_local_fini(void)
{
    g_timer_current_jiffies = (unsigned long long)-1;
    lune_assert(!sched_del_task(s_timer_task_id));
    timer_delete_2nd_htable();
    timer_delete_1st_htable();
}

/*
    avoid POSIX timers for which cpu affinity is out of hand. meanwhile,
    it's said to be bad for realtime applications
*/
typedef struct nrt_timer_period_info {
    lune_time_spec_t next_period;
    long long period_ns;
} nrt_timer_period_info_t;

static void nrt_timer_inc_period(nrt_timer_period_info_t *info) 
{
    info->next_period.tv_nsec += info->period_ns;

    while (info->next_period.tv_nsec >= (long long)1000000000) {
        /* timespec nsec overflow */
        info->next_period.tv_sec++;
        info->next_period.tv_nsec -= (long long)1000000000;
    }
}

static void nrt_timer_init_period_info(nrt_timer_period_info_t *info,
    long long period_ns)
{
    info->period_ns = period_ns;
    clock_gettime(CLOCK_MONOTONIC, &(info->next_period));
}

static void nrt_timer_sleep_till_next_period(nrt_timer_period_info_t *info)
{
    nrt_timer_inc_period(info);

    /* for simplicity, ignoring possibilities of signal wakes */
    clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &info->next_period, NULL);
}

static void *nrt_timer_process_expired_timer(void *data)
{
    lune_nrt_timer_t *tmr = (lune_nrt_timer_t *)data;
    nrt_timer_period_info_t info;
    int err;

    if (0 != (err = cpu_set_affinity(nrt_get_core_id(), CPU_CORE_NRT))) {
        lune_log(LUNE_INFO, "failed to set cpu affinity to NRT timer thread: %s",
            ERR_GET_ERR_STR(err));
        return NULL;
    }

    nrt_timer_init_period_info(&info, tmr->expires);

    if (LUNE_TIMER_ONCE == tmr->type) {
        nrt_timer_sleep_till_next_period(&info);
        tmr->func(tmr->data);
        return NULL;
    }

    lune_assert(LUNE_TIMER_RECURRING == tmr->type);

    while (1) {
        nrt_timer_sleep_till_next_period(&info);
        tmr->func(tmr->data);
    }

    return NULL;
}

int lune_add_nrt_timer(lune_nrt_timer_t *tmr, lune_timer_type_en type,
    unsigned long long expires, lune_timer_func_t func, void *data)
{
    if (unlikely(CORE_IS_RT_CORE())) {
        lune_log(LUNE_INFO, "adding NRT timer on RT core %s",
            CORE_GET_NAME());
        /* fall through */
    }

    if (unlikely(NULL == tmr || 0 == expires || NULL == func)) {
        return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
    }

    tmr->type = type;
    tmr->expires = 1000000000 * expires / LUNE_TIME_GET_HZ();
    tmr->func = func;
    tmr->data = data;

    if (lune_create_thread(&tmr->tid, "NRT timer", nrt_timer_process_expired_timer, (void *)tmr)) {
        lune_log(LUNE_INFO, "failed to create thread for NRT timer: %s",
            strerror(errno));
        return ERR_SET_ERR(LUNE_ERR_SYS_ERR);
    }

    return 0;
}

int lune_del_nrt_timer(lune_nrt_timer_t *tmr)
{
    if (unlikely(CORE_IS_RT_CORE())) {
        lune_log(LUNE_INFO,
            "deleting NRT timer on RT core %s", CORE_GET_NAME());
        /* fall through */
    }

    if (unlikely(NULL == tmr)) {
        return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
    }

    if (lune_delete_thread(&tmr->tid)) {
        lune_log(LUNE_INFO, "failed to delete thread for NRT timer: %s",
            strerror(errno));
        return ERR_SET_ERR(LUNE_ERR_SYS_ERR);
    }

    return 0;
}

int lune_init_timer(lune_timer_t *tmr, lune_timer_type_en type,
    lune_timer_res_en res, lune_timer_func_t func, void *data)
{
    if (unlikely(!CORE_IS_RT_CORE())) {
        return ERR_SET_ERR(LUNE_ERR_NOT_SUPPORTED);
    }

    if (unlikely(NULL == tmr
        || type < LUNE_TIMER_ONCE
        || type > LUNE_TIMER_RECURRING
        || res < LUNE_TIMER_RES_DEFAULT
        || res > LUNE_TIMER_RES_HIGH
        || NULL == func)) {
        return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
    }

    timer_init_timer(tmr, type, res, func, data);
    return 0;
}

int lune_reuse_timer(lune_timer_t *tmr, lune_timer_type_en type,
    lune_timer_res_en res, lune_timer_func_t func, void *data)
{
    if (unlikely(!CORE_IS_RT_CORE())) {
        return ERR_SET_ERR(LUNE_ERR_NOT_SUPPORTED);
    }

    if (unlikely(NULL == tmr
        || type < LUNE_TIMER_ONCE
        || type > LUNE_TIMER_RECURRING
        || res < LUNE_TIMER_RES_DEFAULT
        || res > LUNE_TIMER_RES_HIGH
        || NULL == func)) {
        return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
    }

    timer_reuse_timer(tmr, type, res, func, data);
    return 0;
}

int lune_add_timer(lune_timer_t *tmr, unsigned long long expires)
{
    if (unlikely(!CORE_IS_RT_CORE())) {
        return ERR_SET_ERR(LUNE_ERR_NOT_SUPPORTED);
    }

    if (unlikely(NULL == tmr || !TIMER_IS_VALID_EXPIRES(expires))) {
        return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
    }

    if (unlikely(TIMER_STATUS_INIT != TIMER_GET_STATUS(tmr))) {
        return ERR_SET_ERR(LUNE_ERR_NOT_INIT);
    }

    timer_add_timer(tmr, expires);
    return 0;
}

int lune_mod_timer(lune_timer_t *tmr, unsigned long long expires)
{
    if (unlikely(!CORE_IS_RT_CORE())) {
        return ERR_SET_ERR(LUNE_ERR_NOT_SUPPORTED);
    }

    if (unlikely(NULL == tmr || !TIMER_IS_VALID_EXPIRES(expires))) {
        return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
    }

    if (unlikely(TIMER_STATUS_INIT == TIMER_GET_STATUS(tmr))) {
        return ERR_SET_ERR(LUNE_ERR_NOT_ADDED);
    }

    timer_mod_timer(tmr, expires);
    return 0;
}

int lune_del_timer(lune_timer_t *tmr)
{
    if (unlikely(!CORE_IS_RT_CORE())) {
        return ERR_SET_ERR(LUNE_ERR_NOT_SUPPORTED);
    }

    if (unlikely(NULL == tmr)) {
        return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
    }

    if (unlikely(TIMER_STATUS_INIT == TIMER_GET_STATUS(tmr))) {
        return ERR_SET_ERR(LUNE_ERR_NOT_ADDED);
    }

    timer_del_timer(tmr);
    return 0;
}
