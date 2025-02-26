/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2024 Lune Reseau, Inc.
 */

#ifndef __NRT_H__
#define __NRT_H__

#include "lune/init.h"
#include "lune/log.h"
#include "lune/thread.h"

#include "lib/msgqueue.h"

#define NRT_RT_CONN_MAX_NUM             (64)

#define NRT_REQ_TYPE_LOG                (0)
#define NRT_REQ_TYPE_CAP                (1)
#define NRT_REQ_TYPE_KILL_MSGQ          (2)
#define NRT_REQ_TYPE_CREATE_THREAD      (3)
#define NRT_REQ_TYPE_DELETE_THREAD      (4)

#define NRT_RESP_TYPE_SUCCESS           (0)
#define NRT_RESP_TYPE_FAILURE           (1)

typedef void *(*nrt_thread_func_t)(void *);

typedef struct _nrt_thread {
    char name[LUNE_MAX_SHORT_NAME_BUF_LEN];
    nrt_thread_func_t func;
    void *data;
} nrt_thread_t;

typedef struct _nrt_thread_ins {
    nrt_thread_t thd;
#define NRT_THREAD_UNINIT               (0)
#define NRT_THREAD_INIT_SUCCESS         (1)
#define NRT_THREAD_INIT_FAILURE         (-1)
    int init_flag;
    int exit_flag;
    lune_thread_t tid;
} nrt_thread_ins_t;

/*
    arguments of response function:
    1. response type
    2. response message (if any)
    3. response message length (if any)
    4. error code (if response type is NRT_RESP_TYPE_FAILURE)
    5. response data set while sending request
*/
typedef void (*nrt_resp_func_t)(unsigned int,
    const unsigned char *, unsigned int, int, void *);

#define NRT_THREAD_IS_DELETED()         (g_nrt_curr_thread_ins->exit_flag)
extern __thread nrt_thread_ins_t *g_nrt_curr_thread_ins;

int nrt_local_is_init(void);

int nrt_local_init(unsigned int id);
void nrt_local_fini(void);

int nrt_init(unsigned int core_id);
void nrt_fini(void);

int nrt_is_initialized(void);

unsigned char *nrt_get_req_buf(unsigned int type, unsigned int len);
void nrt_req_buf_done(void);
void nrt_set_resp(unsigned char *req_buf, nrt_resp_func_t resp, void *data);

unsigned int nrt_get_core_id(void);

#endif