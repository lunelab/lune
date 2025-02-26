/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2024 Lune Reseau, Inc.
 */

#ifndef __LUNE_INIT_H__
#define __LUNE_INIT_H__

#ifdef __cplusplus
extern "C" {
#endif

#include "lune/log.h"

typedef struct _lune_conf {
    unsigned int id;            /* NRT core id */
    lune_log_level_en log_level;
    const char *log_file;
} lune_conf_t;

int lune_init(lune_conf_t *conf);
void lune_fini(void);

#ifdef __cplusplus
}
#endif

#endif