/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2024 Lune Reseau, Inc.
 */

#ifdef LUNE_BUILD_DPDK
#include "drv/dpdk/net_if_dpdk.h"
#endif
#include "drv/init.h"
#include "drv/net_if.h"
#include "drv/net_if_virt.h"

int drv_init(void)
{
    int err;

    if (0 != (err = net_if_init())) {
        goto ERR_1;
    }

    if (0 != (err = net_if_virt_init())) {
        goto ERR_2;
    }

#ifdef LUNE_BUILD_DPDK
    if (0 != (err = net_if_dpdk_init())) {
        goto ERR_3;
    }
#endif

    return 0;

#ifdef LUNE_BUILD_DPDK
ERR_3:
    net_if_virt_fini();
#endif

ERR_2:
    net_if_fini();

ERR_1:
    return err;
}

void drv_fini(void)
{
#ifdef LUNE_BUILD_DPDK
    net_if_dpdk_fini();
#endif
    net_if_virt_fini();
    net_if_fini();
}

int drv_local_init(void)
{
#ifdef LUNE_BUILD_DPDK
    return net_if_dpdk_local_init();
#else
    return 0;
#endif
}

void drv_local_fini(void)
{
#ifdef LUNE_BUILD_DPDK
    net_if_dpdk_local_fini();
#endif
}
