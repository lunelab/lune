/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2024 Lune Reseau, Inc.
 */

#ifndef __LUNE_ASSERT_H__
#define __LUNE_ASSERT_H__

#include "lune/os/linux.h"

#ifdef __cplusplus
extern "C" {
#endif

void lune_dump_backtrace(void);

#define lune_assert(expr)                           \
    do {                                            \
        if (unlikely(!(expr))) {                    \
            fprintf(stderr, "lune: %s:%d assertion failed in function %s()\n", \
                __FILE__, __LINE__, __FUNCTION__);  \
            lune_dump_backtrace();                  \
            exit(0);                                \
        }                                           \
    } while (0)

#ifdef __cplusplus
}
#endif

#endif