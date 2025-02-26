/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2024 Lune Reseau, Inc.
 */

#ifndef __LUNE_TIME_H__
#define __LUNE_TIME_H__

#include "lune/assert.h"
#include "lune/os/linux.h"

#ifdef __cplusplus
extern "C" {
#endif

#define LUNE_TIME_MILLISECOND       (g_time_hz / 1000)
#define LUNE_TIME_SECOND            (g_time_hz)
#define LUNE_TIME_MINUTE            (LUNE_TIME_SECOND * 60)
#define LUNE_TIME_HOUR              (LUNE_TIME_MINUTE * 60)
#define LUNE_TIME_DAY               (LUNE_TIME_HOUR * 24)
#define LUNE_TIME_GET_HZ()          (g_time_hz)

#define LUNE_TIME_USEC_PER_CYCLE    (1000000 / g_time_hz)

#define LUNE_DEFAULT_HZ             (10000)
#define LUNE_MAX_HZ                 (100000)
#define LUNE_MIN_HZ                 (1000)

typedef struct timeval lune_time_val_t;
typedef struct timespec lune_time_spec_t;

extern __thread unsigned int g_time_hz;

int lune_get_time_of_day(lune_time_val_t *tv);

#ifdef __cplusplus
}
#endif

#endif