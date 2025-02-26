/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2024 Lune Reseau, Inc.
 */

#ifndef __MSGQUEUE_H__
#define __MSGQUEUE_H__

#include "lune/assert.h"
#include "lune/atomic.h"
#include "lune/common.h"
#include "lune/err.h"
#include "lune/os/linux.h"

typedef struct _msgqueue_msg_hdr {
#define MSGQUEUE_MSG_WRITABLE   (0)
#define MSGQUEUE_MSG_READABLE   (1)
#define MSGQUEUE_MSG_BRIDGE     (2)
    unsigned int flag:2;
    unsigned int len:30;
    unsigned int rsvd_len;
} msgqueue_msg_hdr_t;

#define MSGQUEUE_MSG_LEN(len)   ALIGN_8B(len + sizeof(msgqueue_msg_hdr_t))
#define MSGQUEUE_MSG_MIN_LEN    (256)

typedef struct _msgqueue {
    char name[LUNE_MAX_NAME_BUF_LEN];
    unsigned char *buf;
    unsigned int size;
    unsigned int r_offset;
    unsigned int w_offset;
} msgqueue_t;

typedef struct _msgqueue_bd {
    char name[LUNE_MAX_SHORT_NAME_BUF_LEN];
    msgqueue_t *us;     /* upstream message queue */
    msgqueue_t *ds;     /* downstream message queue */
} msgqueue_bd_t;

int msgqueue_local_init(void);
void msgqueue_local_fini(void);

/*
    creation and deletion of uni-directional message queue
*/
void *msgqueue_create_queue(const char *name, unsigned int size);
void msgqueue_delete_queue(void *queue);

static inline int msgqueue_get_read_buf(void *queue,
    unsigned char **pbuf, unsigned int *plen)
{
    msgqueue_t *msgq = (msgqueue_t *)queue;
    msgqueue_msg_hdr_t *msgh;

    lune_assert(NULL != msgq);

    msgh = (msgqueue_msg_hdr_t *)(msgq->buf + msgq->r_offset);
    if (MSGQUEUE_MSG_BRIDGE == msgh->flag) {
        /* near message queue end */
        msgq->r_offset = 0;
        msgh->flag = MSGQUEUE_MSG_WRITABLE;
        msgh = (msgqueue_msg_hdr_t *)msgq->buf;
    }

    if (MSGQUEUE_MSG_READABLE == msgh->flag) {
        *pbuf = (unsigned char *)msgh + sizeof(msgqueue_msg_hdr_t);
        *plen = msgh->len;
        return 0;
    }

    /*
        ERR_SET_ERR() unneeded as it is normal while attempting to
        retrieve a message from an empty message queue
    */
    return -LUNE_ERR_BUF_EMPTY;
}

static inline void msgqueue_read_buf_done(void *queue)
{
    msgqueue_t *msgq = (msgqueue_t *)queue;
    msgqueue_msg_hdr_t *msgh;

    lune_assert(NULL != msgq);

    msgh = (msgqueue_msg_hdr_t *)(msgq->buf + msgq->r_offset);
    lune_assert(MSGQUEUE_MSG_READABLE == msgh->flag);

    if (msgq->size == (msgq->r_offset + msgh->rsvd_len)) {
        /* reach message queue end */
        msgq->r_offset = 0;
        msgh->flag = MSGQUEUE_MSG_WRITABLE;
        return;
    }

    lune_assert((msgq->r_offset + msgh->rsvd_len) < msgq->size);
    msgq->r_offset += msgh->rsvd_len;
    msgh->flag = MSGQUEUE_MSG_WRITABLE;
    msgh = (msgqueue_msg_hdr_t *)(msgq->buf + msgq->r_offset);
    if (MSGQUEUE_MSG_BRIDGE == msgh->flag) {
        /* near message queue end */
        msgq->r_offset = 0;
        msgh->flag = MSGQUEUE_MSG_WRITABLE;
    }
}

static inline unsigned char *msgqueue_get_write_buf(void *queue, unsigned int len)
{
    msgqueue_t *msgq = (msgqueue_t *)queue;
    msgqueue_msg_hdr_t *msgh, *msgh2;
    unsigned int msg_len;

    lune_assert(NULL != msgq);

    msgh = (msgqueue_msg_hdr_t *)(msgq->buf + msgq->w_offset);

    if (MSGQUEUE_MSG_READABLE == msgh->flag) {
        /* buffer full */
        return NULL;
    }

    lune_assert(MSGQUEUE_MSG_WRITABLE == msgh->flag);

    msg_len = MSGQUEUE_MSG_LEN(len);

    if (msgq->w_offset + msg_len > msgq->size) {
MSGQUEUE_END:
        /* reach message queue end and no enough buffer to accommodate new message */
        msgh->len = 0;
        msgh->rsvd_len = (msgq->size - msgq->w_offset);
        msgq->w_offset = 0;
        msgh->flag = MSGQUEUE_MSG_BRIDGE;

        msgh = (msgqueue_msg_hdr_t *)msgq->buf;
        if (MSGQUEUE_MSG_READABLE == msgh->flag) {
            /* buffer full */
            return NULL;
        }

        lune_assert(MSGQUEUE_MSG_WRITABLE == msgh->flag);
    }

    if (msg_len <= msgh->rsvd_len) {
        msgh->len = len;
        if ((msgh->rsvd_len - msg_len) >= MSGQUEUE_MSG_MIN_LEN) {
            msgh2 = (msgqueue_msg_hdr_t *)((unsigned char *)msgh + msg_len);
            msgh2->flag = MSGQUEUE_MSG_WRITABLE;
            msgh2->len = 0;
            msgh2->rsvd_len = msgh->rsvd_len - msg_len;

            msgh->rsvd_len = msg_len;
        }

        return (unsigned char *)msgh + sizeof(msgqueue_msg_hdr_t);
    }

    while ((msgq->w_offset + msgh->rsvd_len) < msgq->size) {
        msgh2 = (msgqueue_msg_hdr_t *)((unsigned char *)msgh + msgh->rsvd_len);
        if (MSGQUEUE_MSG_READABLE == msgh2->flag) {
            /* no enough buffer to accommodate new message */
            return NULL;
        }

        msgh->rsvd_len += msgh2->rsvd_len;
        if (msg_len <= msgh->rsvd_len) {
            msgh->len = len;
            return (unsigned char *)msgh + sizeof(msgqueue_msg_hdr_t);
        }
    }

    lune_assert((msgq->w_offset + msgh->rsvd_len) == msgq->size);
    goto MSGQUEUE_END;
}

static inline void msgqueue_write_buf_done(void *queue)
{
    msgqueue_t *msgq = (msgqueue_t *)queue;
    msgqueue_msg_hdr_t *msgh;

    lune_assert(NULL != msgq);

    msgh = (msgqueue_msg_hdr_t *)(msgq->buf + msgq->w_offset);

    lune_assert(MSGQUEUE_MSG_WRITABLE == msgh->flag);
    lune_assert((msgq->w_offset + msgh->rsvd_len) <= msgq->size);

    msgq->w_offset = ((msgq->w_offset + msgh->rsvd_len) == msgq->size)
        ? 0: msgq->w_offset + msgh->rsvd_len;
    lune_smp_wmb();
    msgh->flag = MSGQUEUE_MSG_READABLE;
}

/*
    only check sanity of write buffer of message queue
*/
static inline void msgqueue_write_buf_free(void *queue)
{
    msgqueue_t *msgq = (msgqueue_t *)queue;
    msgqueue_msg_hdr_t *msgh;

    lune_assert(NULL != msgq);

    msgh = (msgqueue_msg_hdr_t *)(msgq->buf + msgq->w_offset);

    lune_assert(MSGQUEUE_MSG_WRITABLE == msgh->flag);
    lune_assert((msgq->w_offset + msgh->rsvd_len) <= msgq->size);
}

/*
    creation and deletion of bi-directional message queue
*/
void *msgqueue_create_bd_queue(const char *name,
    unsigned int us_size, unsigned int ds_size);
void msgqueue_delete_bd_queue(void *queue);

static inline int msgqueue_get_us_read_buf(void *bd_queue,
    unsigned char **pbuf, unsigned int *plen)
{
    return msgqueue_get_read_buf(((msgqueue_bd_t *)bd_queue)->us, pbuf, plen);
}

static inline void msgqueue_us_read_buf_done(void *bd_queue)
{
    msgqueue_read_buf_done(((msgqueue_bd_t *)bd_queue)->us);
}

static inline unsigned char *msgqueue_get_us_write_buf(void *bd_queue, unsigned int len)
{
    return msgqueue_get_write_buf(((msgqueue_bd_t *)bd_queue)->us, len);
}

static inline void msgqueue_us_write_buf_done(void *bd_queue)
{
    msgqueue_write_buf_done(((msgqueue_bd_t *)bd_queue)->us);
}

static inline void msgqueue_us_write_buf_free(void *bd_queue)
{
    msgqueue_write_buf_free(((msgqueue_bd_t *)bd_queue)->us);
}

static inline int msgqueue_get_ds_read_buf(void *bd_queue,
    unsigned char **pbuf, unsigned int *plen)
{
    return msgqueue_get_read_buf(((msgqueue_bd_t *)bd_queue)->ds, pbuf, plen);
}

static inline void msgqueue_ds_read_buf_done(void *bd_queue)
{
    msgqueue_read_buf_done(((msgqueue_bd_t *)bd_queue)->ds);
}

static inline unsigned char *msgqueue_get_ds_write_buf(void *bd_queue, unsigned int len)
{
    return msgqueue_get_write_buf(((msgqueue_bd_t *)bd_queue)->ds, len);
}

static inline void msgqueue_ds_write_buf_done(void *bd_queue)
{
    msgqueue_write_buf_done(((msgqueue_bd_t *)bd_queue)->ds);
}

static inline void msgqueue_ds_write_buf_free(void *bd_queue)
{
    msgqueue_write_buf_free(((msgqueue_bd_t *)bd_queue)->ds);
}

#endif