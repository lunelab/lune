/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2024 Lune Reseau, Inc.
 */

#ifndef __COPROC_H_PRE__
#define __COPROC_H_PRE__

#include "lune/os/linux.h"

#include "err/err.h"
#include "lib/msgqueue.h"

typedef struct _coproc_info {
#define COPROC_MAX_CORES            (8)
#define COPROC_MSGQ_SIZE            (0x180000)
    /* upstream: core to coprocessor, downstream: coprocessor to core */
    void *msgq_arrlist;
    unsigned int core_num;
    /*
        lock not necessary for the moment as all the core APIs are required
        to be called in one thread (APIs not thread-safe)
    */
    pthread_spinlock_t lock;
} coproc_t;

#endif

#ifndef __COPROC_H__
#define __COPROC_H__

#include "rt/core.h"

typedef struct _coproc_req_hdr {
#define COPROC_REQ_TYPE_KILL        (0)
#ifdef LUNE_BUILD_SSL
#define COPROC_REQ_TYPE_SSL         (1)
#endif
    unsigned int type;
    unsigned int len;
    unsigned char val[0];
} coproc_req_hdr_t;

typedef struct _coproc_resp_hdr {
#ifdef LUNE_BUILD_SSL
#define COPROC_RESP_TYPE_SSL        (0)
#endif
    unsigned int type;
    unsigned int len;
    unsigned char val[0];
} coproc_resp_hdr_t;

extern __thread msgqueue_bd_t *g_coproc_curr_msgq;

static inline unsigned char *coproc_get_req_buf(msgqueue_bd_t *msgq,
    unsigned int type, unsigned int len)
{
    coproc_req_hdr_t *hdr;

    if (NULL == (hdr = (coproc_req_hdr_t *)msgqueue_get_us_write_buf(msgq,
        sizeof(coproc_req_hdr_t) + len))) {
        ERR_SET_ERR(LUNE_ERR_BUF_FULL);
        return NULL;
    }

    hdr->type = type;
    hdr->len = len;
    return hdr->val;
}

static inline void coproc_req_buf_done(msgqueue_bd_t *msgq)
{
    msgqueue_us_write_buf_done(msgq);
}

static inline void coproc_req_buf_free(msgqueue_bd_t *msgq)
{
    msgqueue_us_write_buf_free(msgq);
}

static inline unsigned char *coproc_get_resp_buf(unsigned int type, unsigned int len)
{
    coproc_resp_hdr_t *hdr;

    if (NULL == (hdr = (coproc_resp_hdr_t *)msgqueue_get_ds_write_buf(g_coproc_curr_msgq,
        sizeof(coproc_resp_hdr_t) + len))) {
        ERR_SET_ERR(LUNE_ERR_BUF_FULL);
        return NULL;
    }

    hdr->type = type;
    hdr->len = len;
    return hdr->val;
}

static inline void coproc_resp_buf_done(void)
{
    msgqueue_ds_write_buf_done(g_coproc_curr_msgq);
}

static inline void coproc_resp_buf_free(void)
{
    msgqueue_ds_write_buf_free(g_coproc_curr_msgq);
}

int coproc_cleanup_core(void);

void coproc_handle_resp(void *data __attribute__((unused)));

int coproc_local_init(void);
void coproc_local_fini(void);

#endif