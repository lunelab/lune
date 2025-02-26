/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2024 Lune Reseau, Inc.
 */

#include "lune/assert.h"
#ifdef LUNE_DEBUG
#include "lune/err.h"
#endif
#include "lune/os/linux.h"

#define ASSERT_BACKTRACE_ENTRY_SIZE     (256)

void lune_dump_backtrace()
{
    void *buf[ASSERT_BACKTRACE_ENTRY_SIZE];
    char **strings;
    int nptrs;

#ifdef LUNE_DEBUG
    lune_dump_err(LUNE_ERR_DUMP_TO_STDERR);
#endif

    nptrs = backtrace(buf, ASSERT_BACKTRACE_ENTRY_SIZE);
    if ((strings = backtrace_symbols(buf, nptrs))) {
        while (nptrs-- > 0) {
            fprintf(stdout, "%s\n", strings[nptrs]);
        }
        free(strings);
    }
}
