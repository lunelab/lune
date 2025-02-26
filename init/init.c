/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2024 Lune Reseau, Inc.
 */

#include "lune/assert.h"
#include "lune/init.h"
#include "lune/log.h"
#include "lune/os/linux.h"

#include "drv/aggr.h"
#ifdef LUNE_BUILD_DPDK
#include "drv/dpdk/net_if_dpdk.h"
#endif
#include "drv/init.h"
#include "kernel/init.h"
#include "kernel/sched.h"
#include "kernel/time.h"
#include "lib/init.h"
#include "log/log.h"
#include "mem/mem.h"
#include "net/init.h"
#include "nrt/nrt.h"
#include "res/cpu.h"
#include "rt/core.h"

int lune_init(lune_conf_t *conf)
{
    int err, log_init_flag = 0;
    const char *mod_str;

    if (NULL == conf
        || (conf->log_level < LUNE_CRIT
        || conf->log_level >= LUNE_LOG_LEVEL_NUM)) {
        err = ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        mod_str = "lune";
        goto ERR_1;
    }

    if (0 != (err = cpu_init())) {
        mod_str = "cpu";
        goto ERR_1;
    }

    if (0 != (err = mem_init())) {
        mod_str = "mem";
        goto ERR_2;
    }

    if (0 != (err = time_init())) {
        mod_str = "time";
        goto ERR_3;
    }

    if (0 != (err = log_init(conf->log_file, conf->log_level))) {
        mod_str = "log";
        goto ERR_4;
    }

    log_init_flag = 1;

    if (0 != (err = nrt_init(conf->id))) {
        mod_str = "non-realtime thread";
        goto ERR_5;
    }

    if (0 != (err = aggr_init())) {
        mod_str = "aggregator";
        goto ERR_6;
    }

    if (0 != (err = core_init())) {
        mod_str = "lune core";
        goto ERR_7;
    }

    if (0 != (err = lib_init())) {
        mod_str = "library";
        goto ERR_8;
    }

    if (0 != (err = net_init())) {
        mod_str = "network";
        goto ERR_9;
    }

    if (0 != (err = drv_init())) {
        mod_str = "driver";
        goto ERR_10;
    }

    /* bind main thread to NRT cpu core */
    if (0 != (err = cpu_set_affinity(conf->id, CPU_CORE_NRT))) {
        lune_log(LUNE_INFO, "failed to set cpu affinity to main thread: %s", ERR_GET_ERR_STR(err));
        /* keep going */
    }

    return 0;

ERR_10:
    net_fini();

ERR_9:
    lib_fini();

ERR_8:
    core_fini();

ERR_7:
    aggr_fini();

ERR_6:
    nrt_fini();

ERR_5:
    lune_log(LUNE_CRIT, "%s init failed: %s", mod_str, ERR_GET_ERR_STR(err));
    log_fini();

ERR_4:
    time_fini();

ERR_3:
    mem_fini();

ERR_2:
    cpu_fini();

ERR_1:
    if (!log_init_flag) {
        fprintf(stderr, "%s init failed: %s\n", mod_str, ERR_GET_ERR_STR(err));
    }

    exit(EXIT_FAILURE);
}

void lune_fini(void)
{
    drv_fini();
    net_fini();
    lib_fini();
    core_fini();
    aggr_fini();
    nrt_fini();
    log_fini();
    time_fini();
    mem_fini();
    cpu_fini();

    fflush(stdout);
}
