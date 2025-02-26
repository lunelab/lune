/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2024 Lune Reseau, Inc.
 */

#ifndef __LOG_H__
#define __LOG_H__

#include "lune/log.h"

#define LOG_IS_CPU_USAGE_ON()       (g_log_cpu_usage_flag)
#define LOG_SET_CPU_USAGE_OFF()     do {    \
        g_log_cpu_usage_flag = 0;           \
    } while (0)
#define LOG_SET_CPU_USAGE_ON()     do {     \
        g_log_cpu_usage_flag = 1;           \
    } while (0)

extern __thread unsigned int g_log_cpu_usage_flag;

unsigned char log_get_id(void);
lune_log_level_en log_get_level(void);

int log_local_init(const char *log_file, lune_log_level_en log_level);
void log_local_fini(void);

void log_cleanup(unsigned char id);

int log_init(const char *log_file, lune_log_level_en log_level);
void log_fini(void);

lune_log_level_en log_get_log_level(const char ch);

int log_process_nrt_msg(const unsigned char *msg, unsigned int msg_len);

void log_flush(void);

#endif