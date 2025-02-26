/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2024 Lune Reseau, Inc.
 */

#ifndef __RINGBUF_H__
#define __RINGBUF_H__

#include "lune/assert.h"
#include "lune/atomic.h"
#include "lune/common.h"
#include "lune/err.h"
#include "lune/os/linux.h"

typedef struct _ringbuf_hdr {
#define RINGBUF_PKT_WRITABLE        (0)
#define RINGBUF_PKT_READABLE        (1)
#define RINGBUF_PKT_WRITING         (2)
    unsigned int flag;
    unsigned int len;
} ringbuf_hdr_t;

typedef struct _ringbuf {
    char name[LUNE_MAX_SHORT_NAME_BUF_LEN];
    unsigned char *buf;
    unsigned int frame_size;
    unsigned int frame_num;
    unsigned int r_idx;
    union {
        unsigned int w_idx;
        lune_atomic32_t w_idx_mt;
    };
} ringbuf_t;

#pragma pack(8)
typedef struct _ringbuf_frm {
    unsigned char *buf;
    unsigned int len;
} ringbuf_frm_t;
#pragma pack()

#define ringbuf_create_buf(name, frm_num, frm_size)     __ringbuf_create_buf(name, frm_num, frm_size, 0)
#define ringbuf_delete_buf(rb)                          __ringbuf_delete_buf(rb)

static inline unsigned int ringbuf_get_read_frm_burst(void *p,
    ringbuf_frm_t *frms, unsigned int frm_cnt)
{
    ringbuf_t *rb = (ringbuf_t *)p;
    ringbuf_hdr_t *rbh;
    unsigned int cnt = 0, r_idx = rb->r_idx;

    while (cnt < frm_cnt) {
        rbh = (ringbuf_hdr_t *)(rb->buf + r_idx * rb->frame_size);
        if (RINGBUF_PKT_READABLE != rbh->flag) {
            break;
        }

        frms->buf = (unsigned char *)rbh + sizeof(ringbuf_hdr_t);
        frms->len = rbh->len;
        frms++;
        r_idx = (r_idx + 1) % rb->frame_num;
        cnt++;
    }

    return cnt;
}

static inline int ringbuf_get_read_frm(void *p, unsigned char **pfrm, unsigned int *plen)
{
    ringbuf_t *rb = (ringbuf_t *)p;
    ringbuf_hdr_t *rbh;

    rbh = (ringbuf_hdr_t *)(rb->buf + rb->r_idx * rb->frame_size);
    if (likely(RINGBUF_PKT_READABLE == rbh->flag)) {
        *pfrm = (unsigned char *)rbh + sizeof(ringbuf_hdr_t);
        *plen = rbh->len;
        return 0;
    }

    /*
        ERR_SET_ERR() unneeded as it is normal while attempting to
        retrieve a message from an empty message queue
    */
    return -LUNE_ERR_BUF_EMPTY;
}

static inline void ringbuf_read_frm_done(void *p, unsigned char *frm)
{
    ringbuf_t *rb = (ringbuf_t *)p;
    ringbuf_hdr_t *rbh;

    lune_smp_rmb();
    rbh = (ringbuf_hdr_t *)(frm - sizeof(ringbuf_hdr_t));

#ifdef LUNE_DEBUG
    lune_assert(RINGBUF_PKT_READABLE == rbh->flag);
#endif

    rb->r_idx = (rb->r_idx + 1) % rb->frame_num;
    rbh->flag = RINGBUF_PKT_WRITABLE;
}

static inline unsigned char *ringbuf_get_write_frm(void *p, unsigned int len)
{
    ringbuf_t *rb = (ringbuf_t *)p;
    ringbuf_hdr_t *rbh;

#ifdef LUNE_DEBUG
    lune_assert((len + sizeof(ringbuf_hdr_t)) <= rb->frame_size);
#endif

    rbh = (ringbuf_hdr_t *)(rb->buf + rb->w_idx * rb->frame_size);

    if (unlikely(RINGBUF_PKT_WRITABLE != rbh->flag)) {
        /* buffer full */
        return NULL;
    }

    rb->w_idx = (rb->w_idx + 1) % rb->frame_num;
    rbh->len = len;

    return (unsigned char *)rbh + sizeof(ringbuf_hdr_t);
}

static inline void ringbuf_write_frm_done(void *p __attribute__((unused)),
    unsigned char *w_buf)
{
    ringbuf_hdr_t *rbh;

    lune_smp_wmb();
    rbh = (ringbuf_hdr_t *)(w_buf - sizeof(ringbuf_hdr_t));
    rbh->flag = RINGBUF_PKT_READABLE;
}

#define ringbuf_create_buf_mt(name, frm_num, frm_size)  __ringbuf_create_buf(name, frm_num, frm_size, 1)
#define ringbuf_delete_buf_mt(p)                        __ringbuf_delete_buf(p)
#define ringbuf_get_read_frm_burst_mt(p, frms, frm_cnt) ringbuf_get_read_frm_burst(p, frms, frm_cnt)
#define ringbuf_get_read_frm_mt(p, pfrm, plen)          ringbuf_get_read_frm_mt(p, pfrm, plen)
#define ringbuf_read_frm_done_mt(p, frm)                ringbuf_read_frm_done(p, frm)

static inline int ringbuf_get_write_frm_mt(void *p, unsigned int len, unsigned char **pfrm)
{
    ringbuf_t *rb = (ringbuf_t *)p;
    ringbuf_hdr_t *rbh;
    unsigned int w_idx;

#ifdef LUNE_DEBUG
    lune_assert((len + sizeof(ringbuf_hdr_t)) <= rb->frame_size);
#endif

    w_idx = (unsigned int)lune_atomic32_inc_and_return(&rb->w_idx_mt);
    rbh = (ringbuf_hdr_t *)(rb->buf + (w_idx % rb->frame_num) * rb->frame_size);
    *pfrm = (unsigned char *)rbh + sizeof(ringbuf_hdr_t);

    if (unlikely(RINGBUF_PKT_WRITABLE != rbh->flag)) {
        /* buffer full */
        return ERR_SET_ERR(LUNE_ERR_BUF_FULL);
    }

    rbh->len = len;

    return 0;
}

/*
    check frame status and see if reading is done, update length field if yes
*/
static inline int ringbuf_check_and_update_write_frm_mt(unsigned char *frm, unsigned int len)
{
    ringbuf_hdr_t *rbh = (ringbuf_hdr_t *)(frm - sizeof(ringbuf_hdr_t));

    if (RINGBUF_PKT_WRITABLE == rbh->flag) {
        rbh->len = len;
        return 0;
    } else {
        /* ERR_SET_ERR() unneeded as the check may be attempted multiple times */
        return -LUNE_ERR_BUF_FULL;
    }
}

#define ringbuf_write_frm_done_mt(p, buf)   ringbuf_write_frm_done(p, buf)

void *__ringbuf_create_buf(const char *name,
    unsigned int frm_num, unsigned int frm_size, unsigned int is_mt);
void __ringbuf_delete_buf(void *p);

#endif