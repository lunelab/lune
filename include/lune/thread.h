/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2024 Lune Reseau, Inc.
 */

#ifndef __LUNE_THREAD_H__
#define __LUNE_THREAD_H__

#include "lune/assert.h"
#include "lune/common.h"
#include "lune/err.h"
#include "lune/os/linux.h"

#define LUNE_LINUX_PTHREAD_MAX_NAME_LEN         (15)
#define LUNE_LINUX_PTHREAD_MAX_NAME_BUF_LEN     (LUNE_LINUX_PTHREAD_MAX_NAME_LEN + 1)

typedef struct _lune_thread {
    pthread_t tid;
    char name[LUNE_LINUX_PTHREAD_MAX_NAME_BUF_LEN];
} lune_thread_t;

static inline int lune_create_thread(lune_thread_t *thread,
    const char *name,
    void *(*start_routine)(void *),
    void *arg)
{
    int err;

    if (unlikely(NULL == thread
        || NULL == name
        || NULL == start_routine)) {
        err = lune_set_err_no(LUNE_ERR_INVALID_ARG);
        goto ERR_1;
    }

    if (strlen(name) > LUNE_LINUX_PTHREAD_MAX_NAME_BUF_LEN) {
        err = lune_set_err_no(LUNE_ERR_NAME_TOO_LONG);
        goto ERR_1;
    }

    if (pthread_create(&thread->tid, NULL, start_routine, arg)) {
        err = lune_set_err_no(LUNE_ERR_SYS_ERR);
        goto ERR_1;
    }

    if (pthread_setname_np(thread->tid, name)) {
        err = lune_set_err_no(LUNE_ERR_SYS_ERR);
        goto ERR_2;
    }

    strcpy(thread->name, name);

    return 0;

ERR_2:
    lune_assert(!pthread_cancel(thread->tid));
    lune_assert(!pthread_join(thread->tid, NULL));

ERR_1:
    return err;
}

static inline int lune_delete_thread(lune_thread_t *thread)
{
    int err;

    if (unlikely(NULL == thread)) {
        err = lune_set_err_no(LUNE_ERR_INVALID_ARG);
        goto ERR_1;
    }

    if (pthread_cancel(thread->tid)) {
        err = lune_set_err_no(LUNE_ERR_SYS_ERR);
        goto ERR_1;
    }

    if (pthread_join(thread->tid, NULL)) {
        err = lune_set_err_no(LUNE_ERR_SYS_ERR);
        goto ERR_1;
    }

    return 0;

ERR_1:
    return err;
}

#endif