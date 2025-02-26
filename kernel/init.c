/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2024 Lune Reseau, Inc.
 */

#include "kernel/init.h"

#include "kernel/time.h"
#include "kernel/sched.h"
#include "kernel/timer.h"

int kernel_local_init(void)
{
    int err;

    /* sched_local_init must be called before timer_local_init since timer_local_init will need to add a task */
    if (0 != (err = sched_local_init())) {
        goto ERR_1;
    }

    if (0 != (err = timer_local_init())) {
        goto ERR_2;
    }

    return 0;

ERR_2:
    sched_local_fini();

ERR_1:
    return err;
}

void kernel_local_fini(void)
{
    timer_local_fini();
    sched_local_fini();
}

