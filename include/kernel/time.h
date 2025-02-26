/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2024 Lune Reseau, Inc.
 */

#ifndef __TIME_H__
#define __TIME_H__

#include "lune/assert.h"
#include "lune/log.h"
#include "lune/os/linux.h"
#include "lune/time.h"

#define TIME_HZ                             (g_time_hz)
#define TIME_LOG_BUF_SIZE                   (256)

#define TIME_NS_PER_SEC                     (1E9)
#define TIME_US_PER_SEC                     (1E6)

typedef unsigned long long time_tick_t;

static inline unsigned long long read_tsc(void)
{
    unsigned int hi, lo;
    asm volatile("rdtsc" : "=a" (lo), "=d" (hi));
    return ((unsigned long long)hi << 32) | lo;
}

extern lune_time_val_t g_init_tv;
extern unsigned long long g_init_tsc;

extern unsigned long long g_tsc_per_usec;
extern unsigned long long g_tsc_per_sec;
extern unsigned long long g_tsc_per_min_hz;

extern __thread unsigned long long g_tsc_per_cycle;
extern __thread unsigned long long g_tsc_last_cycle_of_min_hz;
extern __thread unsigned long long g_tsc_last_cycle_of_sec;
extern __thread unsigned long long g_tsc_per_cuto;
extern __thread unsigned long long g_tsc_per_cutb;

static inline void time_get_time_of_day(lune_time_val_t *tv)
{
    unsigned long long curr_tsc = read_tsc();
    long long tsc_delta = (long long)(curr_tsc - g_init_tsc);
    long long secs = tsc_delta / g_tsc_per_sec;
    long long usecs = (tsc_delta % g_tsc_per_sec) / g_tsc_per_usec;

    tv->tv_usec = g_init_tv.tv_usec + usecs;
    tv->tv_sec = g_init_tv.tv_sec + secs;
    if (tv->tv_usec >= 1000000) {
#ifdef LUNE_DEBUG
        lune_assert(tv->tv_usec < 2000000);
#endif
        tv->tv_sec += 1;
        tv->tv_usec -= 1000000;
    }
}

#define time_log_time_of_day(fmt, ...)      \
    do {                                    \
        lune_time_val_t tv;                 \
        char time_fmt[TIME_LOG_BUF_SIZE];   \
        strcpy(time_fmt, "[%ld.%06ld] ");   \
        strcat(time_fmt, fmt);              \
        time_get_time_of_day(&tv);          \
        lune_log(LUNE_INFO, time_fmt, tv.tv_sec, tv.tv_usec, ##__VA_ARGS__);  \
    } while (0)

int time_init(void);
void time_fini(void);

int time_local_init(unsigned int hz);
void time_local_fini(void);

#define TIME_GET_CLK_TICK(t)                    do { *(t) = read_tsc(); } while (0)
/*
    Get end tick (till overall threshold) in current cycle.
    It's called periodically at the starting point of each cycle.
*/
#define TIME_GET_TH_BE_TICKS(t_start)           ((t_start) + g_tsc_per_cutb)
#define TIME_GET_TH_OA_TICKS(t_start)           ((t_start) + g_tsc_per_cuto)
#define TIME_GET_TICKS_PER_TH_BE()              (g_tsc_per_cutb)
#define TIME_GET_TICKS_PER_TH_OA()              (g_tsc_per_cuto)
#define TIME_GET_TICKS_PER_CYCLE()              (g_tsc_per_cycle)
#define TIME_GET_TICKS_PER_SEC()                (g_tsc_per_sec)
#define TIME_GET_TICKS_PER_MIN_HZ()             (g_tsc_per_min_hz)
#define TIME_GET_TICKS_LAST_CYCLE_OF_MIN_HZ()   (g_tsc_last_cycle_of_min_hz)
#define TIME_GET_TICKS_LAST_CYCLE_OF_SEC()      (g_tsc_last_cycle_of_sec)
#define TIME_GET_CPU_USAGE_PER_CYCLE(t_start, t_end)    \
    ((float)((t_end) - (t_start)) / g_tsc_per_cycle)
#define TIME_GET_TICKS_DELTA(t1, t2)            \
    ((long long)((unsigned long long)(t1) - (unsigned long long)(t2)))

#define TIME_IS_INIT()                          (0 != g_time_hz)

#define TIME_BEFORE(t1, t2)                     \
    (((long long)((unsigned long long)(t2) - (unsigned long long)(t1))) > 0)
#define TIME_AFTER(t1, t2)                      \
    (((long long)((unsigned long long)(t1) - (unsigned long long)(t2))) > 0)
#define TIME_SHIFT_DELTA(t, delta)              \
    do { t = ((unsigned long long)((long long)(t) + (long long)(delta))); } while (0)

static inline time_tick_t time_sleep_till_next_cycle(time_tick_t t_start,
    unsigned long long tsc_per_cycle)
{
    time_tick_t t, t_end = t_start + tsc_per_cycle;

    while (1) {
        TIME_GET_CLK_TICK(&t);
        if (t >= t_end) {
            break;
        }
    }

    return t;
}

#endif