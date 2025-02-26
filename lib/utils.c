/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2024 Lune Reseau, Inc.
 */

#include "lune/os/linux.h"

#include "lib/utils.h"

unsigned int utils_get_datetime(char *buf, unsigned int size)
{
    time_t rawtime;
    struct tm * timeinfo;

    time(&rawtime);
    timeinfo = localtime(&rawtime);

    return strftime(buf, size, "%F %T", timeinfo);
}
