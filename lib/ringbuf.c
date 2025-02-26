/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2024 Lune Reseau, Inc.
 */

#include "lune/err.h"
#include "lune/mem.h"
#include "lune/os/linux.h"

#include "err/err.h"
#include "lib/ringbuf.h"

#define RINGBUF_IS_VALID_SIZE(s)    IS_POW2_NUM(s)

void *__ringbuf_create_buf(const char *name,
    unsigned int frm_num, unsigned int frm_size, unsigned int is_mt)
{
    ringbuf_t *rb;
    unsigned int i;

    if (NULL == name || 0 == frm_num || 0 == frm_size) {
        ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        goto ERR_1;
    }

    if (strlen(name) > LUNE_MAX_SHORT_NAME_LEN) {
        ERR_SET_ERR(LUNE_ERR_NAME_TOO_LONG);
        goto ERR_1;
    }

    if (NULL == (rb = lune_malloc(sizeof(ringbuf_t)))) {
        goto ERR_1;
    }

    rb->frame_num = frm_num;
    rb->frame_size = ALIGN_8B(frm_size + sizeof(ringbuf_hdr_t));
    if (NULL == (rb->buf = lune_malloc(rb->frame_size * rb->frame_num))) {
        goto ERR_2;
    }

    for (i = 0; i < rb->frame_num; i++) {
        ringbuf_hdr_t *rbh;
        rbh = (ringbuf_hdr_t *)(rb->buf + i * rb->frame_size);
        rbh->flag = RINGBUF_PKT_WRITABLE;
    }

    strcpy(rb->name, name);
    rb->r_idx = 0;
    if (is_mt) {
        lune_atomic32_set(&rb->w_idx_mt, -1);
    } else {
        rb->w_idx = 0;
    }

    return rb;

ERR_2:
    lune_free(rb);

ERR_1:
    return NULL;
}

void __ringbuf_delete_buf(void *p)
{
    lune_free(((ringbuf_t *)p)->buf);
    lune_free(p);
}
