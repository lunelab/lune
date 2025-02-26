/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2024 Lune Reseau, Inc.
 */

#include "lib/conv.h"
#include "lib/htable.h"
#include "lib/init.h"
#include "lib/idlist.h"
#include "lib/idtable.h"
#include "lib/msgqueue.h"

int lib_local_init(void)
{
    int err;

    if (0 != (err = idlist_local_init())) {
        goto ERR_1;
    }

    if (0 != (err = idtable_local_init())) {
        goto ERR_2;
    }

    if (0 != (err = htable_local_init())) {
        goto ERR_3;
    }

    if (0 != (err = msgqueue_local_init())) {
        goto ERR_4;
    }

    return 0;

ERR_4:    
    htable_local_fini();

ERR_3:
    idtable_local_fini();

ERR_2:
    idlist_local_fini();

ERR_1:
    return err;
}

void lib_local_fini(void)
{
    msgqueue_local_fini();
    htable_local_fini();
    idtable_local_fini();
    idlist_local_fini();
}

int lib_init(void)
{
    int err;

    if (0 != (err = conv_init())) {
        goto ERR_1;
    }

    return 0;

ERR_1:
    return err;
}

void lib_fini(void)
{
    conv_fini();
}
