/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2024 Lune Reseau, Inc.
 */

#include "lune/err.h"
#include "lune/time.h"

#include "err/err.h"
#include "kernel/sched.h"
#include "kernel/time.h"
#include "log/log.h"
#include "rt/core.h"

lune_time_val_t g_init_tv;
unsigned long long g_init_tsc;

__thread unsigned int g_time_hz = 0;

unsigned long long g_tsc_per_usec;
unsigned long long g_tsc_per_sec;
unsigned long long g_tsc_per_min_hz;

__thread unsigned long long g_tsc_per_cycle;
__thread unsigned long long g_tsc_last_cycle_of_min_hz;
__thread unsigned long long g_tsc_last_cycle_of_sec;
__thread unsigned long long g_tsc_per_cuto;     /* tsc per cpu usage threshold overall */
__thread unsigned long long g_tsc_per_cutb;     /* tsc per cpu usage threshold best-effort */

static int time_calibrate(void)
{
    long long t_usec;
    double t_sec;
    unsigned long long tsc_start, tsc_end;
    lune_time_spec_t ts_start, ts_end;
    /* sleep 1/10 seconds */
    lune_time_spec_t sleep_time = { .tv_nsec = TIME_NS_PER_SEC / 10 };

    if (clock_gettime(CLOCK_MONOTONIC_RAW, &ts_start)) {
        return ERR_SET_ERR(LUNE_ERR_SYS_ERR);
    }

    tsc_start = read_tsc();
    nanosleep(&sleep_time, NULL);
    clock_gettime(CLOCK_MONOTONIC_RAW, &ts_end);
    tsc_end = read_tsc();

    t_usec = (ts_end.tv_sec - ts_start.tv_sec) * TIME_US_PER_SEC
        + (ts_end.tv_nsec - ts_start.tv_nsec) / 1000;
    t_sec = (double)t_usec / TIME_US_PER_SEC;
    g_init_tv.tv_sec = ts_start.tv_sec;
    g_init_tv.tv_usec = ts_start.tv_nsec / 1000;
    g_init_tsc = tsc_start;

    g_tsc_per_usec = ((long long)(tsc_end - tsc_start)) / t_usec;
    g_tsc_per_sec = (unsigned long long)(((long long)(tsc_end - tsc_start)) / t_sec);
    g_tsc_per_min_hz = g_tsc_per_sec / LUNE_MIN_HZ;

    g_tsc_per_cycle = g_tsc_per_sec / g_time_hz;
    g_tsc_last_cycle_of_min_hz = g_tsc_per_cycle
        + (g_tsc_per_min_hz % g_tsc_per_cycle);
    g_tsc_last_cycle_of_sec = g_tsc_last_cycle_of_min_hz
        + (g_tsc_per_sec % g_tsc_per_min_hz);
    g_tsc_per_cuto = (unsigned long long)(g_tsc_per_cycle * SCHED_CPU_USAGE_TH_OA);
    g_tsc_per_cutb = (unsigned long long)(g_tsc_per_cycle * SCHED_CPU_USAGE_TH_BE);

#ifdef LUNE_DEBUG
    fprintf(stdout, "tsc per microsecond: %lld\n", g_tsc_per_usec);
    fprintf(stdout, "tsc per second: %lld\n", g_tsc_per_sec);
    fprintf(stdout, "tsc per cpu usage threshold overall: %lld\n", g_tsc_per_cuto);
    fprintf(stdout, "tsc per cpu usage threshold best-effort: %lld\n", g_tsc_per_cutb);
    fprintf(stdout, "tsc of last cycle of %d hz frequency: %lld\n",
        LUNE_MIN_HZ, g_tsc_last_cycle_of_min_hz);
    fprintf(stdout, "tsc of last cycle of a second: %lld\n", g_tsc_last_cycle_of_sec);
#endif

    return 0;
}

/* called by main thread */
int time_init(void)
{
    memset(&g_init_tv, 0x00, sizeof(lune_time_val_t));
    g_init_tsc = 0;

    g_time_hz = LUNE_DEFAULT_HZ;

    g_tsc_per_usec = 0;
    g_tsc_per_sec = 0;
    g_tsc_per_min_hz = 0;

    g_tsc_per_cycle = 0;
    g_tsc_last_cycle_of_min_hz = g_tsc_last_cycle_of_sec = 0;
    g_tsc_per_cuto = g_tsc_per_cutb = 0;

    return time_calibrate();
}

void time_fini(void)
{
    g_time_hz = 0;
}

int time_local_init(unsigned int hz)
{
    g_time_hz = hz;

    g_tsc_per_cycle = g_tsc_per_sec / g_time_hz;
    g_tsc_last_cycle_of_min_hz = g_tsc_per_cycle
        + (g_tsc_per_min_hz % g_tsc_per_cycle);
    g_tsc_last_cycle_of_sec = g_tsc_last_cycle_of_min_hz
        + (g_tsc_per_sec % g_tsc_per_min_hz);
    g_tsc_per_cuto = (unsigned long long)(g_tsc_per_cycle * SCHED_CPU_USAGE_TH_OA);
    g_tsc_per_cutb = (unsigned long long)(g_tsc_per_cycle * SCHED_CPU_USAGE_TH_BE);

    lune_log(LUNE_DBG, "ticks per cycle on core %s: %lld",
        CORE_GET_NAME(), g_tsc_per_cycle);

    return 0;
}

void time_local_fini(void)
{
    g_time_hz = 0;
}

int lune_get_time_of_day(lune_time_val_t *tv)
{
    if (unlikely(NULL == tv)) {
        return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
    }

    time_get_time_of_day(tv);
    return 0;
}
