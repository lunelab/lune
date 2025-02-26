/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2024 Lune Reseau, Inc.
 */

#ifndef __CORE_H_PRE__
#define __CORE_H_PRE__

#include "lune/common.h"
#include "lune/core.h"
#include "lune/id.h"
#include "lune/thread.h"

#include "lib/arrlist.h"
#include "lib/msgqueue.h"

msgqueue_bd_t *core_get_coproc_msgqueue(unsigned int cp_idx);

#endif

#ifndef __CORE_H__
#define __CORE_H__

#include "rt/coproc.h"

typedef enum _core_ins_state {
    CORE_INS_STATE_IDLE = 0,
    CORE_INS_STATE_STARTING,
    CORE_INS_STATE_RUNNING,
    CORE_INS_STATE_QUITTING,
    CORE_INS_STATE_QUITTED,
} core_ins_state_en;

#define CORE_IS_CORE_RUNNING(id)            (CORE_INS_STATE_RUNNING == g_core_ins_array[id].state)
#define CORE_IS_CORE_NA(id)                 (LUNE_CORE_NA == g_core_ins_array[id].conf.type)
#define CORE_IS_CORE_NP(id)                 (LUNE_CORE_NP == g_core_ins_array[id].conf.type)
#define CORE_IS_CORE_CP(id)                 (LUNE_CORE_CP == g_core_ins_array[id].conf.type)
#define CORE_IS_LOCAL_CORE_ID(id)           (g_core_ins == &g_core_ins_array[id])
#define CORE_GET_CORE_INS(id)               (&g_core_ins_array[id])

#define CORE_IS_RT_CORE()                   (NULL != g_core_ins)

#define CORE_IS_RUNNING()                   (CORE_IS_RT_CORE() && CORE_INS_STATE_RUNNING == g_core_ins->state)
#define CORE_IS_QUITTING()                  (CORE_IS_RT_CORE() && CORE_INS_STATE_QUITTING == g_core_ins->state)
#define CORE_RELOAD_IS_NEEDED()             (CORE_IS_RT_CORE() && g_core_ins->reload_flags)

#define CORE_IS_NA()                        (LUNE_CORE_NA == g_core_ins->conf.type)
#define CORE_IS_NP()                        (LUNE_CORE_NP == g_core_ins->conf.type)
#define CORE_IS_CP()                        (LUNE_CORE_CP == g_core_ins->conf.type)
#define CORE_GET_CP_INFO()                  \
    ((LUNE_CORE_CP == g_core_ins->conf.type)   \
    ? &g_core_ins->cp : NULL)
#define CORE_IS_INS_CP_BOUND(ci)            \
    (LUNE_CORE_NP == (ci)->conf.type   \
    && NULL != (ci)->np.cp_arrlist)
#define CORE_IS_CP_BOUND()                  CORE_IS_INS_CP_BOUND(g_core_ins)

#define CORE_IS_EXIT_REQUIRED()             (g_core_ins->exit_flag)
#define CORE_GET_NAME()                     (g_core_ins->name)
#define CORE_GET_ID()                       (NULL == g_core_ins ? (-1) : (int)g_core_ins->conf.id)
#define CORE_SET_QUITTING()                 do {    \
        g_core_ins->state = CORE_INS_STATE_QUITTING;\
    } while (0)

#define CORE_NP_MAX_BOUND_CP_NUM            (16)

#define CORE_NP_IS_CP_ACTIVE(cp_idx)        \
    ((cp_idx) < CORE_NP_MAX_BOUND_CP_NUM    \
    && NULL != g_core_ins->np.cp_arrlist    \
    && ARRLIST_ELEM_EXIST(ARRLIST_GET_ELEM_BY_IDX(g_core_ins->np.cp_arrlist, (cp_idx))))

#define CORE_NP_FOR_EACH_CP_SAFE(cp, cp2)   \
    ARRLIST_FOR_EACH_NODE_SAFE(g_core_ins->np.cp_arrlist, (cp), (cp2))
#define CORE_NP_GET_CP_MSGQ(cp, pmsgq)      do {    \
        unsigned int cp_idx = ARRLIST_GET_NODE_IDX(cp); \
        *pmsgq = core_get_coproc_msgqueue(cp_idx);  \
    } while (0)

typedef struct _net_proc_bound_cp {
    /* CP core id */
    unsigned int id;
    /* message queue between NP and CP */
    unsigned int msgq_idx;
} net_proc_bound_cp_t;

typedef struct _net_proc_info {
    void *cp_arrlist;
    unsigned int cp_task_id;
} net_proc_t;

/* lune core instance */
typedef struct _core_ins {
#define CORE_INS_NAME_BUF_LEN               (16)
    char name[CORE_INS_NAME_BUF_LEN];
    lune_core_conf_t conf;
    lune_thread_t tid;
    core_ins_state_en state;
    /* upstream: app -> core, downstream: core -> app */
#define CORE_INS_MSGQ_SIZE                  (0x10000)
    msgqueue_bd_t *msgq;
    union {
        net_proc_t np;
        coproc_t cp;
    };
#define CORE_INS_RELOAD_FLAG_ON(ci, flag)           \
    (((struct _core_ins *)(ci))->reload_flags & (flag))
#define CORE_INS_RELOAD_SET_FLAG(ci, flag)          \
    do { ((struct _core_ins *)(ci))->reload_flags |= (flag); } while (0)
#define CORE_INS_RELOAD_CLEAR_FLAG(ci, flag)        \
    do { ((struct _core_ins *)(ci))->reload_flags &= (~flag); } while (0)
#define CORE_INS_RELOAD_FLAG_CP_BOUND               0x00000001
#define CORE_INS_RELOAD_CP_BOUND_ON(ci)             \
    CORE_INS_RELOAD_FLAG_ON(ci, CORE_INS_RELOAD_FLAG_CP_BOUND)
#define CORE_INS_RELOAD_CP_BOUND_SET_ON(ci)         \
    CORE_INS_RELOAD_SET_FLAG(ci, CORE_INS_RELOAD_FLAG_CP_BOUND)
#define CORE_INS_RELOAD_CP_BOUND_SET_OFF(ci)        \
    CORE_INS_RELOAD_CLEAR_FLAG(ci, CORE_INS_RELOAD_FLAG_CP_BOUND)
    unsigned short reload_flags;

    unsigned short exit_flag;
    int err;
} core_ins_t;

extern __thread core_ins_t *g_core_ins;
extern core_ins_t g_core_ins_array[LUNE_MAX_CORE_NUM];

unsigned char *core_get_coproc_req_buf(unsigned int cp_idx,
    unsigned int type, unsigned int len);
void core_coproc_req_buf_done(unsigned int cp_idx);

int core_cleanup_core(void);

int core_reload_conf(void);

int core_init(void);
void core_fini(void);

unsigned int core_get_next_bound_cp_idx(void);

unsigned char *core_get_core_req_send_buf(unsigned int id, unsigned int len);
void core_req_send_buf_done(unsigned int id);
int core_get_core_req_recv_buf(unsigned char **pbuf, unsigned int *plen);
void core_req_recv_buf_done(void);

unsigned char *core_get_core_resp_send_buf(unsigned int len);
void core_resp_send_buf_done(void);
int core_get_core_resp_recv_buf(unsigned int id, unsigned char **pbuf, unsigned int *plen);
void core_resp_recv_buf_done(unsigned int id);

#endif