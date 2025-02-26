/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2024 Lune Reseau, Inc.
 */

#ifndef __LUNE_LOG_H__
#define __LUNE_LOG_H__

#define LUNE_LOG_DEFAULT_LEVEL  (LUNE_INFO)

#ifdef __cplusplus
extern "C" {
#endif

typedef enum _lune_log_level {
    LUNE_CRIT = 0,  /* critical */
    LUNE_WARN = 1,  /* warning */
    LUNE_INFO = 2,  /* information */
    LUNE_DBG = 3,   /* debug */
    LUNE_VBS = 4,   /* verbose */
    LUNE_LOG_LEVEL_NUM = 5,
    LUNE_INVALID_LOG_LEVEL = 5,
} lune_log_level_en;

#define lune_log(level, ...)        \
    do { __lune_log(__FILE__, __LINE__, 0, (level), __VA_ARGS__); } while (0)
#define lune_log_once(level, ...)   \
    do { __lune_log(__FILE__, __LINE__, 1, (level), __VA_ARGS__); } while (0)

int __lune_log(const char *file_name,
    int line_num, int squash, lune_log_level_en level, const char *fmt, ...);

#ifdef __cplusplus
}
#endif

#endif