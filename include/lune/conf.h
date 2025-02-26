/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2024 Lune Reseau, Inc.
 */

#ifndef __LUNE_CONF_H__
#define __LUNE_CONF_H__

#ifdef __cplusplus
extern "C" {
#endif

/*
    for build of LUNE and its built-in APPs, use build_conf.h generated during the build
    for build of any other independent APP, use build_conf.h already installed
*/
#ifdef LUNE_BUILD
#include "build/build_conf.h"
#else
#include "lune/build_conf.h"
#endif

/* macro to compute a version number usable for comparisons */
#define LUNE_VER_NUM(a, b, c, d)    ((a) << 24 | (b) << 16 | (c) << 8 | (d))

/* all version numbers in one to compare with LUNE_VER_NUM() */
#define LUNE_VERSION                \
    LUNE_VER_NUM(                   \
    LUNE_VER_MAJOR,                 \
    LUNE_VER_MINOR,                 \
    LUNE_VER_REV,                   \
    0)

unsigned short lune_conf_get_max_mtu(void);

const char *lune_get_version(void);

#ifdef __cplusplus
}
#endif

#endif