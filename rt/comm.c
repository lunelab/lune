/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2024 Lune Reseau, Inc.
 */

#include "lune/os/linux.h"

#include "kernel/sched.h"
#include "res/cpu.h"
#include "rt/comm.h"
#include "rt/core.h"

#define COMM_CORE_MAX_REQ_HANDLE_PER_CYCLE      (4)

typedef struct _comm_core_req_hdr {
    lune_comm_req_type_en type;
    unsigned int len;
    unsigned char val[0];
} comm_core_req_hdr_t;

typedef struct _comm_core_resp_hdr {
    lune_comm_resp_type_en type;
    unsigned int len;
    int err;
    unsigned int rsvd;
    unsigned char val[0];
} comm_core_resp_hdr_t;

static __thread unsigned int s_comm_core_req_handle_task_id;

comm_core_req_handler_t g_comm_core_req_handler_array[LUNE_COMM_REQ_MAX] = {{0}};

int comm_send_req_to_core(unsigned int id,
    lune_comm_req_type_en type, const void *val, unsigned int len)
{
    unsigned char *p;

    if (unlikely(CORE_IS_RT_CORE())) {
        return ERR_SET_ERR(LUNE_ERR_NOT_SUPPORTED);
    }

    if (unlikely(!CPU_IS_VALID_CPU_ID(id)
        || (NULL == val && 0 != len)
        || (NULL != val && 0 == len))) {
        return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
    }

    if (unlikely(!CORE_IS_CORE_RUNNING(id))) {
        return ERR_SET_ERR(LUNE_ERR_CORE_NOT_RUNNING);
    }

    if (NULL == (p = core_get_core_req_send_buf(id, len + sizeof(comm_core_req_hdr_t)))) {
        return ERR_GET_LAST_ERR();
    }

    ((comm_core_req_hdr_t *)p)->type = type;
    ((comm_core_req_hdr_t *)p)->len = len;
    if (len > 0) {
        memcpy(p + sizeof(comm_core_req_hdr_t), val, len);
    }
    core_req_send_buf_done(id);

    return 0;
}

int comm_recv_resp_from_core(unsigned int id,
    lune_comm_resp_type_en *ptype, int *perr, void *pval, unsigned int *plen)
{
    unsigned char *p;
    unsigned int len;
    int err;

    if (unlikely(CORE_IS_RT_CORE())) {
        return ERR_SET_ERR(LUNE_ERR_NOT_SUPPORTED);
    }

    if (unlikely(!CPU_IS_VALID_CPU_ID(id)
        || NULL == ptype
        || NULL == perr)) {
        return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
    }

    if (!CORE_IS_CORE_RUNNING(id)) {
        return ERR_SET_ERR(LUNE_ERR_CORE_NOT_RUNNING);
    }

    if (0 != (err = core_get_core_resp_recv_buf(id, &p, &len))) {
        return err;
    }

    *ptype = ((comm_core_resp_hdr_t *)p)->type;
    *perr = ((comm_core_resp_hdr_t *)p)->err;
    lune_assert(0 <= (len = (len - sizeof(comm_core_resp_hdr_t))));
    if (0 != len && NULL != pval) {
        lune_assert(NULL != plen);
        if (*plen >= len) {
            memcpy(pval, p + sizeof(comm_core_resp_hdr_t), len);
        } else {
            memcpy(pval, p + sizeof(comm_core_resp_hdr_t), *plen);
        }
    }

    if (NULL != plen) {
        *plen = len;
    }

    core_resp_recv_buf_done(id);
    return 0;
}

int comm_core_send_resp(lune_comm_resp_type_en type,
    const void *val, unsigned int len, int err)
{
    unsigned char *p;

    if (unlikely(!CORE_IS_RT_CORE())) {
        return ERR_SET_ERR(LUNE_ERR_NOT_SUPPORTED);
    }

    if (NULL == (p = core_get_core_resp_send_buf(len + sizeof(comm_core_resp_hdr_t)))) {
        return ERR_GET_LAST_ERR();
    }

    ((comm_core_resp_hdr_t *)p)->type = type;
    ((comm_core_resp_hdr_t *)p)->len = len;
    ((comm_core_resp_hdr_t *)p)->err = err;
    if (len > 0) {
        memcpy(p + sizeof(comm_core_resp_hdr_t), val, len);
    }
    core_resp_send_buf_done();

    return 0;
}

static void comm_core_handle_req(void *p __attribute__((unused)))
{
    unsigned char *buf;
    unsigned int len;
    int cnt;

    cnt = 0;
    while (!core_get_core_req_recv_buf(&buf, &len)
        && cnt < COMM_CORE_MAX_REQ_HANDLE_PER_CYCLE) {
        comm_core_req_hdr_t *hdr = (comm_core_req_hdr_t *)buf;

        if (unlikely(hdr->type < LUNE_COMM_REQ_ADD_NET_IF
            && hdr->type >= LUNE_COMM_REQ_MAX)) {
            /* drop it */
            lune_log(LUNE_INFO, "received message of request type %d with the length",
                hdr->type, hdr->len);
        } else {
            lune_assert(NULL != g_comm_core_req_handler_array[hdr->type].func);
            g_comm_core_req_handler_array[hdr->type].func(buf + sizeof(comm_core_req_hdr_t),
                len - sizeof(comm_core_req_hdr_t));
        }

        core_req_recv_buf_done();
        cnt++;
    }
}

int comm_local_init(void)
{
    if (LUNE_INVALID_ID == (s_comm_core_req_handle_task_id = sched_add_task("timer",
        comm_core_handle_req, NULL, SCHED_PRIO_NORMAL))) {
        return ERR_GET_LAST_ERR();
    }

    return 0;
}

void comm_local_fini(void)
{
    lune_assert(!sched_del_task(s_comm_core_req_handle_task_id));
}

int lune_reg_comm_req_handler(lune_comm_req_type_en type, lune_comm_req_handle_func_t func)
{
    if (type < LUNE_COMM_REQ_APP
        || type >= LUNE_COMM_REQ_MAX) {
        return ERR_SET_ERR(LUNE_ERR_NOT_SUPPORTED);
    }

    if (NULL == func) {
        return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
    }

    if (NULL != g_comm_core_req_handler_array[type].func) {
        lune_log(LUNE_INFO, "handler of request type %d already registered", type);
        return ERR_SET_ERR(LUNE_ERR_ALREADY_SET);
    }

    g_comm_core_req_handler_array[type].func = func;
    return 0;
}

int lune_unreg_comm_req_handler(lune_comm_req_type_en type)
{
    if (type < LUNE_COMM_REQ_APP
        || type >= LUNE_COMM_REQ_MAX) {
        return ERR_SET_ERR(LUNE_ERR_NOT_SUPPORTED);
    }

    if (NULL == g_comm_core_req_handler_array[type].func) {
        lune_log(LUNE_INFO, "handler of request type %d not registered", type);
        return ERR_SET_ERR(LUNE_ERR_NOT_SET);
    }

    g_comm_core_req_handler_array[type].func = NULL;
    return 0;
}
