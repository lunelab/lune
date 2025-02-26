/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2024 Lune Reseau, Inc.
 */

#include "lune/err.h"
#include "lune/mem.h"
#include "lune/os/linux.h"

#include "err/err.h"
#include "kernel/sched.h"
#include "kernel/time.h"
#include "lib/common.h"
#include "lib/msgqueue.h"
#include "log/log.h"
#include "nrt/nrt.h"
#include "res/cpu.h"
#include "utils/cap.h"

typedef struct _nrt_conf {
    unsigned int core_id;
} nrt_conf_t;

#pragma pack(8)
typedef struct _nrt_req_hdr {
    unsigned int type;
    unsigned int len;
    nrt_resp_func_t resp;
    void *resp_data;
    unsigned char val[0];
} nrt_req_hdr_t;

typedef struct _nrt_resp_hdr {
    unsigned short type;
    unsigned short len;
    int err;
    nrt_resp_func_t resp;
    void *resp_data;
    unsigned char val[0];
} nrt_resp_hdr_t;

typedef struct _nrt_kill_msg_hdr {
    unsigned char log_id;
} nrt_kill_msg_hdr_t;
#pragma pack()

__thread nrt_thread_ins_t *g_nrt_curr_thread_ins = NULL;

#define NRT_REQ_HANDLER_UNINIT          (0)
#define NRT_REQ_HANDLER_INIT_SUCCESS    (1)
#define NRT_REQ_HANDLER_INIT_FAILURE    (-1)
static int s_nrt_req_handler_init_flag = NRT_REQ_HANDLER_UNINIT;

static int s_nrt_req_handler_exit_flag = 0;

lune_thread_t s_nrt_tid;

#define NRT_MSGQ_US_SIZE                (0x2000000)
#define NRT_MSGQ_DS_SIZE                (0x2000)

#define NRT_LOG_FLUSH_PERIOD_IN_USECS   (1000000)

static nrt_conf_t s_nrt_conf = {0};
static pthread_spinlock_t s_nrt_msgqueue_lock;
static unsigned int s_nrt_msgqueue_offset = 0;
static void *s_nrt_msgqueue_array[NRT_RT_CONN_MAX_NUM] = {0};
/*
    RT: message queue communicating with NRT core
    NRT: message queue communicating with certain RT core with message being processed
*/
static __thread void *s_nrt_msgqueue = NULL;
static __thread unsigned int s_nrt_resp_handler_task_id = LUNE_INVALID_ID;

static void *nrt_create_msgqueue(const char *name)
{
    int i = 0;
    void *msgq;

    pthread_spin_lock(&s_nrt_msgqueue_lock);
    while (i < NRT_RT_CONN_MAX_NUM) {
        if (NULL == s_nrt_msgqueue_array[s_nrt_msgqueue_offset]) {
            if (NULL == (s_nrt_msgqueue_array[s_nrt_msgqueue_offset] =
                msgqueue_create_bd_queue(name, NRT_MSGQ_US_SIZE, NRT_MSGQ_DS_SIZE))) {
                pthread_spin_unlock(&s_nrt_msgqueue_lock);
                lune_log(LUNE_WARN, "failed to create message queue %s: %s",
                    name, ERR_GET_LAST_ERR_STR());
                return NULL;
            }

            pthread_spin_unlock(&s_nrt_msgqueue_lock);

            msgq = s_nrt_msgqueue_array[s_nrt_msgqueue_offset];
            s_nrt_msgqueue_offset = (s_nrt_msgqueue_offset + 1) % NRT_RT_CONN_MAX_NUM;
            return msgq;
        }

        s_nrt_msgqueue_offset = (s_nrt_msgqueue_offset + 1) % NRT_RT_CONN_MAX_NUM;
        i++;
    }

    pthread_spin_unlock(&s_nrt_msgqueue_lock);
    lune_log(LUNE_INFO, "failed to create message queue %s: %s",
        name, ERR_GET_ERR_STR(ERR_SET_ERR(LUNE_ERR_EXCEED_LIMITS)));
    return NULL;
}

static void nrt_delete_msgqueue(void *msgq)
{
    msgqueue_delete_bd_queue(msgq);
}

static void *nrt_thread_runner(void *data)
{
    int err;
    nrt_thread_ins_t *ins = (nrt_thread_ins_t *)data;
    void *p;

    lune_assert(NULL != ins);

    if (0 != (err = cpu_set_affinity(s_nrt_conf.core_id, CPU_CORE_NRT))) {
        lune_log(LUNE_WARN, "failed to set cpu affinity to non-realtime thread: %s",
            ERR_GET_ERR_STR(err));
        ins->init_flag = NRT_THREAD_INIT_FAILURE;
        return NULL;
    }

    ins->init_flag = NRT_THREAD_INIT_SUCCESS;
    ins->exit_flag = 0;
    g_nrt_curr_thread_ins = ins;

    p = ins->thd.func(ins->thd.data);
    if (ins->exit_flag) {
        /* thread deletion message received */
        ins->exit_flag = 0;
    }

    return p;
}

static void nrt_create_thread(nrt_req_hdr_t *req_hdr)
{
    nrt_thread_t *thd = (nrt_thread_t *)req_hdr->val;
    nrt_thread_ins_t *ins;
    unsigned int sleep_usecs = 1000;
    nrt_resp_hdr_t *resp_hdr;
    int err;

    lune_assert(NULL != s_nrt_msgqueue);
    lune_assert(NULL != thd);
    lune_assert(NULL != thd->func);
    lune_assert(NULL != thd->name);

    if (NULL == (ins = lune_malloc(sizeof(nrt_thread_ins_t)))) {
        err = ERR_GET_LAST_ERR();
        goto ERR_1;
    }

    strcpy(ins->thd.name, thd->name);
    ins->thd.func = thd->func;
    ins->thd.data = thd->data;
    ins->init_flag = NRT_THREAD_UNINIT;

    if (lune_create_thread(&ins->tid, "NRT thread", nrt_thread_runner, ins)) {
        err = ERR_SET_ERR(LUNE_ERR_SYS_ERR);
        goto ERR_2;
    }

    while (NRT_THREAD_UNINIT == ins->init_flag) {
        /* sleep till thread is initialized or failed to do so */
        usleep(sleep_usecs);
    }

    if (NRT_THREAD_INIT_FAILURE == ins->init_flag) {
        err = ERR_SET_ERR(LUNE_ERR_SYS_ERR);
        goto ERR_2;
    }

    if (NULL == req_hdr->resp) {
        /* response event not set */
        return;
    }

    while (NULL == (resp_hdr = (nrt_resp_hdr_t *)msgqueue_get_ds_write_buf(s_nrt_msgqueue,
        sizeof(nrt_resp_hdr_t) + sizeof(nrt_thread_ins_t *)))) {
        /* wait till response buffer available */
        usleep(sleep_usecs);
    }

    resp_hdr->type = NRT_RESP_TYPE_SUCCESS;
    resp_hdr->len = sizeof(nrt_thread_ins_t *);
    resp_hdr->err = 0;
    resp_hdr->resp = req_hdr->resp;
    resp_hdr->resp_data = req_hdr->resp_data;
    *(nrt_thread_ins_t **)resp_hdr->val = ins;
    msgqueue_ds_write_buf_done(s_nrt_msgqueue);

    return;

ERR_2:
    lune_free(ins);

ERR_1:
    if (NULL == req_hdr->resp) {
        /* response event not set */
        return;
    }

    while (NULL == (resp_hdr = (nrt_resp_hdr_t *)msgqueue_get_ds_write_buf(s_nrt_msgqueue,
        sizeof(nrt_resp_hdr_t)))) {
        /* wait till response buffer available */
        usleep(sleep_usecs);
    }

    resp_hdr->type = NRT_RESP_TYPE_FAILURE;
    resp_hdr->len = 0;
    resp_hdr->err = err;
    resp_hdr->resp = req_hdr->resp;
    resp_hdr->resp_data = req_hdr->resp_data;
    msgqueue_ds_write_buf_done(s_nrt_msgqueue);
}

static void nrt_delete_thread(nrt_req_hdr_t *req_hdr)
{
    nrt_thread_ins_t *ins = *(nrt_thread_ins_t **)req_hdr->val;
    int retries = 5;
    unsigned int sleep_usecs = 5000;
    nrt_resp_hdr_t *resp_hdr;

    lune_assert(NULL != ins);
    lune_assert(!ins->exit_flag);
    ins->exit_flag = 1;

    do {
        usleep(sleep_usecs);
    } while (ins->exit_flag && --retries >= 0);

    if (ins->exit_flag) {
        if (lune_delete_thread(&ins->tid)) {
            lune_log(LUNE_INFO, "failed to delete thread for NRT timer: %s",
                strerror(errno));
        }
    }

    lune_free(ins);

    if (NULL == req_hdr->resp) {
        /* response event not set */
        return;
    }

    while (NULL == (resp_hdr = (nrt_resp_hdr_t *)msgqueue_get_ds_write_buf(s_nrt_msgqueue,
        sizeof(nrt_resp_hdr_t)))) {
        /* wait till response buffer available */
        usleep(sleep_usecs);
    }

    resp_hdr->type = NRT_RESP_TYPE_SUCCESS;
    resp_hdr->len = 0;
    resp_hdr->err = 0;
    resp_hdr->resp = req_hdr->resp;
    resp_hdr->resp_data = req_hdr->resp_data;
    msgqueue_ds_write_buf_done(s_nrt_msgqueue);
}

unsigned char *nrt_get_req_buf(unsigned int type, unsigned int len)
{
    nrt_req_hdr_t *hdr;

    if (NULL == (hdr = (nrt_req_hdr_t *)msgqueue_get_us_write_buf(s_nrt_msgqueue,
        len + sizeof(nrt_req_hdr_t)))) {
        return NULL;
    }

    hdr->type = type;
    hdr->len = len;
    hdr->resp = NULL;
    hdr->resp_data = NULL;

    return (unsigned char *)hdr->val;
}

void nrt_set_resp(unsigned char *req_buf, nrt_resp_func_t resp, void *data)
{
    nrt_req_hdr_t *hdr = (nrt_req_hdr_t *)(req_buf - sizeof(nrt_req_hdr_t));
#ifdef LUNE_DEBUG
    lune_assert(NULL == hdr->resp);
    lune_assert(NULL == hdr->resp_data);
    lune_assert(NULL != resp);
#endif
    hdr->resp = resp;
    hdr->resp_data = data;
}

void nrt_req_buf_done(void)
{
    msgqueue_us_write_buf_done(s_nrt_msgqueue);
}

/*
    this is non-realtime thread which processes messages of non-realtime tasks
    such as writing logs to file, writing captured packets to file and so on
*/
static void *nrt_req_handler(void *p __attribute__((unused)))
{
    unsigned int sleep_usecs = 1000, log_flush_usecs = 0;
    int i, err;

    if (0 != (err = cpu_set_affinity(s_nrt_conf.core_id, CPU_CORE_NRT))) {
        lune_log(LUNE_CRIT, "failed to set cpu affinity to non-realtime thread: %s",
            ERR_GET_ERR_STR(err));
        s_nrt_req_handler_init_flag = NRT_REQ_HANDLER_INIT_FAILURE;
        return NULL;
    }

    s_nrt_req_handler_init_flag = NRT_REQ_HANDLER_INIT_SUCCESS;

    while (!s_nrt_req_handler_exit_flag) {
        nrt_req_hdr_t *hdr;
        unsigned int len;

        for (i = 0; i < NRT_RT_CONN_MAX_NUM; i++) {
            if (NULL != s_nrt_msgqueue_array[i]) {
                unsigned int del_queue_flag = 0;

                s_nrt_msgqueue = s_nrt_msgqueue_array[i];
                while (!msgqueue_get_us_read_buf(s_nrt_msgqueue,
                    (unsigned char **)&hdr, &len)) {
                    lune_assert((hdr->len + sizeof(nrt_req_hdr_t)) == len);

                    switch (hdr->type) {
                    case NRT_REQ_TYPE_LOG:
                        (void)log_process_nrt_msg((const unsigned char *)hdr->val, hdr->len);
                        break;
                    case NRT_REQ_TYPE_CAP:
                        (void)cap_process_nrt_msg((const unsigned char *)hdr->val, hdr->len);
                        break;
                    case NRT_REQ_TYPE_KILL_MSGQ:
                        log_cleanup(((nrt_kill_msg_hdr_t *)hdr->val)->log_id);
                        del_queue_flag = 1;
                        break;
                    case NRT_REQ_TYPE_CREATE_THREAD:
                        lune_assert(sizeof(nrt_thread_t) == hdr->len);
                        nrt_create_thread(hdr);
                        break;
                    case NRT_REQ_TYPE_DELETE_THREAD:
                        lune_assert(sizeof(void *) == hdr->len);
                        nrt_delete_thread(hdr);
                        break;
                    default:
                        break;
                    }

                    msgqueue_us_read_buf_done(s_nrt_msgqueue);

                    if (del_queue_flag) {
                        nrt_delete_msgqueue(s_nrt_msgqueue_array[i]);
                        s_nrt_msgqueue_array[i] = NULL;
                        break;
                    }
                }
                s_nrt_msgqueue = NULL;
            }
        }

        usleep(sleep_usecs);

        log_flush_usecs += sleep_usecs;
        if (log_flush_usecs >= NRT_LOG_FLUSH_PERIOD_IN_USECS) {
            log_flush_usecs = 0;
            log_flush();
        }
    }

    s_nrt_req_handler_exit_flag = 0;

    return NULL;
}

static void nrt_resp_handler(void *p __attribute__((unused)))
{
    nrt_resp_hdr_t *hdr;
    unsigned int len;

    if (!msgqueue_get_ds_read_buf(s_nrt_msgqueue, (unsigned char **)&hdr, &len)) {
#ifdef LUNE_DEBUG
        lune_assert(NULL != hdr->resp);
        lune_assert(NULL != hdr->resp_data);
#endif
        hdr->resp(hdr->type, hdr->val, hdr->len, hdr->err, hdr->resp_data);
        msgqueue_ds_read_buf_done(s_nrt_msgqueue);
    }
}

int nrt_is_initialized(void)
{
    return (NRT_REQ_HANDLER_INIT_SUCCESS == s_nrt_req_handler_init_flag);
}

static int nrt_kill_msgqueue(void)
{
    nrt_kill_msg_hdr_t *hdr;

    if (NULL == (hdr = (nrt_kill_msg_hdr_t *)nrt_get_req_buf(NRT_REQ_TYPE_KILL_MSGQ,
        sizeof(nrt_kill_msg_hdr_t)))) {
        return ERR_SET_ERR(LUNE_ERR_BUF_FULL);
    }

    hdr->log_id = log_get_id();

    nrt_req_buf_done();
    return 0;
}

int nrt_local_is_init(void)
{
    return (s_nrt_msgqueue != NULL);
}

int nrt_local_init(unsigned int id)
{
    char name[LUNE_MAX_SHORT_NAME_BUF_LEN];

    sprintf(name, "nrt queue %d", id);
    if (NULL == (s_nrt_msgqueue = nrt_create_msgqueue(name))) {
        goto ERR_1;
    }

    sprintf(name, "nrt resp handler %d", id);
    if (LUNE_INVALID_ID == (s_nrt_resp_handler_task_id = sched_add_task(name,
        (lune_task_func_t)nrt_resp_handler, NULL, SCHED_PRIO_NORMAL))) {
        lune_log(LUNE_WARN, "failed to add nrt resp handler task on core %d: %s",
            id, ERR_GET_LAST_ERR_STR());
        goto ERR_2;
    }

    return 0;

ERR_2:
    nrt_delete_msgqueue(s_nrt_msgqueue);
    s_nrt_msgqueue = NULL;

ERR_1:
    return ERR_GET_LAST_ERR();
}

void nrt_local_fini(void)
{
    unsigned int sleep_usecs = 1000;

    lune_assert(!sched_del_task(s_nrt_resp_handler_task_id));
    s_nrt_resp_handler_task_id = LUNE_INVALID_ID;

    while (0 != nrt_kill_msgqueue()) {
        /* Zzz... wait till msgqueue unfull */
        usleep(sleep_usecs);
    }

    s_nrt_msgqueue = NULL;
}

int nrt_init(unsigned int core_id)
{
    unsigned int sleep_usecs = 1000;

    if (0 != pthread_spin_init(&s_nrt_msgqueue_lock, PTHREAD_PROCESS_PRIVATE)) {
        ERR_SET_ERR(LUNE_ERR_SYS_ERR);
        lune_log(LUNE_CRIT, "failed to initialize NRT message queue lock: %s", strerror(errno));
        goto ERR_1;
    }

    if (0 != cap_init()) {
        goto ERR_2;
    }

    s_nrt_conf.core_id = core_id;

    s_nrt_req_handler_init_flag = NRT_REQ_HANDLER_UNINIT;
    s_nrt_req_handler_exit_flag = 0;

    if (lune_create_thread(&s_nrt_tid, "NRT req handler", nrt_req_handler, NULL)) {
        ERR_SET_ERR(LUNE_ERR_SYS_ERR);
        lune_log(LUNE_CRIT, "failed to create NRT thread: %s", strerror(errno));
        goto ERR_3;
    }

    while (NRT_REQ_HANDLER_UNINIT == s_nrt_req_handler_init_flag) {
        /* sleep till thread is initialized or failed to do so */
        usleep(sleep_usecs);
    }

    if (NRT_REQ_HANDLER_INIT_SUCCESS != s_nrt_req_handler_init_flag) {
        ERR_SET_ERR(LUNE_ERR_SYS_ERR);
        goto ERR_3;
    }

    return 0;

ERR_3:
    cap_fini();

ERR_2:
    lune_assert(!pthread_spin_destroy(&s_nrt_msgqueue_lock));

ERR_1:
    return ERR_GET_LAST_ERR();
}

void nrt_fini(void)
{
    unsigned int sleep_usecs = 1000;

    s_nrt_req_handler_exit_flag = 1;
    do {
        usleep(sleep_usecs);
    } while (s_nrt_req_handler_exit_flag); 

    cap_fini();

    lune_assert(!pthread_spin_destroy(&s_nrt_msgqueue_lock));
}

unsigned int nrt_get_core_id(void)
{
    return s_nrt_conf.core_id;
}
