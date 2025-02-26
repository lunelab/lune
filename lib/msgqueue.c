/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2024 Lune Reseau, Inc.
 */

#include "lune/err.h"
#include "lune/mem.h"
#include "lune/os/linux.h"

#include "err/err.h"
#include "lib/msgqueue.h"

#define MSGQUEUE_IS_VALID_SIZE(s)   IS_POW2_NUM((s) & 0xffff)

int msgqueue_local_init(void)
{
    return 0;
}

void msgqueue_local_fini(void)
{
    return;
}

void *msgqueue_create_queue(const char *name, unsigned int size)
{
    msgqueue_t *msgq;
    msgqueue_msg_hdr_t *msgh;

    if (NULL == name) {
        ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        return NULL;
    }

    if (strlen(name) > LUNE_MAX_NAME_LEN) {
        ERR_SET_ERR(LUNE_ERR_NAME_TOO_LONG);
        return NULL;
    }

    if (!MSGQUEUE_IS_VALID_SIZE(size)) {
        ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        return NULL;
    }

    if (NULL == (msgq = lune_malloc_mt(sizeof(msgqueue_t)))) {
        goto ERR_1;
    }

    if (NULL == (msgq->buf = lune_malloc_x_mt(size))) {
        goto ERR_2;
    }

    strcpy(msgq->name, name);
    msgq->size = size;
    msgq->r_offset = msgq->w_offset = 0;

    msgh = (msgqueue_msg_hdr_t *)msgq->buf;
    msgh->flag = MSGQUEUE_MSG_WRITABLE;
    msgh->len = 0;
    msgh->rsvd_len = msgq->size;

    return msgq;

ERR_2:
    lune_free_mt(msgq);

ERR_1:
    return NULL;
}

void msgqueue_delete_queue(void *queue)
{
    lune_free_x_mt(((msgqueue_t *)queue)->buf);
    lune_free_mt(queue);
}

void *msgqueue_create_bd_queue(const char *name,
    unsigned int us_size, unsigned int ds_size)
{
    msgqueue_bd_t *msgq;
    char tmp_name[LUNE_MAX_NAME_BUF_LEN];

    if (NULL == name) {
        ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        return NULL;
    }

    if (strlen(name) > LUNE_MAX_SHORT_NAME_LEN) {
        ERR_SET_ERR(LUNE_ERR_NAME_TOO_LONG);
        return NULL;
    }

    if (!MSGQUEUE_IS_VALID_SIZE(us_size)
        || !MSGQUEUE_IS_VALID_SIZE(ds_size)) {
        ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        return NULL;
    }

    if (NULL == (msgq = lune_malloc_mt(sizeof(msgqueue_bd_t)))) {
        goto ERR_1;
    }

    sprintf(tmp_name, "%s_us", name);
    if (NULL == (msgq->us = msgqueue_create_queue(tmp_name, us_size))) {
        goto ERR_2;
    }

    sprintf(tmp_name, "%s_ds", name);
    if (NULL == (msgq->ds = msgqueue_create_queue(tmp_name, ds_size))) {
        goto ERR_3;
    }

    strcpy(msgq->name, name);
    return msgq;

ERR_3:
    msgqueue_delete_queue(msgq->us);

ERR_2:
    lune_free_mt(msgq);

ERR_1:
    return NULL;
}

void msgqueue_delete_bd_queue(void *queue)
{
    msgqueue_delete_queue(((msgqueue_bd_t *)queue)->ds);
    msgqueue_delete_queue(((msgqueue_bd_t *)queue)->us);
    lune_free_mt(queue);
}
