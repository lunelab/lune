/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2024 Lune Reseau, Inc.
 */

#include "lune/conf.h"
#include "lune/net_if.h"

const char *lune_get_version(void)
{
    static char version[32] = {0};

    if (version[0] != 0) {
        return version;
    }

    snprintf(version, sizeof(version), "%s %d.%d.%d",
        LUNE_VER_PREFIX,
        LUNE_VER_MAJOR,
        LUNE_VER_MINOR,
        LUNE_VER_REV);

    return version;
}

unsigned short lune_conf_get_max_mtu(void)
{
    return LUNE_NET_IF_MAX_MTU;
}
