/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2024 Lune Reseau, Inc.
 */

#include "lune/id.h"
#include "lune/log.h"
#include "lune/os/linux.h"

#include "err/err.h"
#include "lib/arrlist.h"
#include "kernel/sched.h"
#ifdef LUNE_BUILD_SSL
#include "net/ossl.h"
#endif
#include "rt/coproc.h"
#include "rt/core.h"

static __thread unsigned int s_coproc_task_id = LUNE_INVALID_ID;

__thread msgqueue_bd_t *g_coproc_curr_msgq = NULL;

int coproc_cleanup_core(void)
{
#ifdef LUNE_BUILD_SSL
    ossl_local_fini();
#endif
    lune_assert(!sched_del_task(s_coproc_task_id));
    s_coproc_task_id = LUNE_INVALID_ID;
    return 0;
}

static void coproc_handle_req(coproc_t *cpi)
{
    coproc_req_hdr_t *hdr;
    unsigned int len;
    void *n, *n2;

    pthread_spin_lock(&cpi->lock);
    ARRLIST_FOR_EACH_NODE_SAFE(cpi->msgq_arrlist, n, n2) {
        pthread_spin_unlock(&cpi->lock);
        g_coproc_curr_msgq =
            *(msgqueue_bd_t **)ARRLIST_GET_ELEM_BY_NODE(n);
#ifdef LUNE_DEBUG
        lune_assert(NULL != g_coproc_curr_msgq);
#endif
        while (!msgqueue_get_us_read_buf(g_coproc_curr_msgq,
            (unsigned char **)&hdr, &len)) {
            lune_assert((hdr->len + sizeof(coproc_req_hdr_t)) == len);
            switch (hdr->type) {
            case COPROC_REQ_TYPE_KILL:
                msgqueue_us_read_buf_done(g_coproc_curr_msgq);
                msgqueue_delete_bd_queue(g_coproc_curr_msgq);
                pthread_spin_lock(&cpi->lock);
                arrlist_s_list_free_elem(cpi->msgq_arrlist, ARRLIST_GET_ELEM_BY_NODE(n));
                cpi->core_num--;
                /* no response required as the other end has stopped listening, just kill it */
                goto NEXT_MSGQ;
#ifdef LUNE_BUILD_SSL
            case COPROC_REQ_TYPE_SSL:
            {
                int err;

                if (0 != (err = ossl_handle_coproc_req(
                        (const unsigned char *)hdr->val, hdr->len))) {
                    lune_log(LUNE_INFO, "failed to handle ssl coprocessing request "
                        "on core %s: %s", CORE_GET_NAME(), ERR_GET_ERR_STR(err));
                }
                break;
            }
#endif
            default:
                lune_log(LUNE_INFO, "received unexpected coprocessing request "
                    "on core %s: %d", CORE_GET_NAME(), hdr->type);
                break;
            }
            msgqueue_us_read_buf_done(g_coproc_curr_msgq);
        }
        pthread_spin_lock(&cpi->lock);
NEXT_MSGQ:
        do {;} while (0);
    }
    pthread_spin_unlock(&cpi->lock);

    g_coproc_curr_msgq = NULL;
}

void coproc_handle_resp(void *data __attribute__((unused)))
{
    coproc_resp_hdr_t *hdr;
    unsigned int len;
    msgqueue_bd_t *msgq;
    void *cp, *cp2;

    lune_assert(CORE_IS_CP_BOUND());

    CORE_NP_FOR_EACH_CP_SAFE(cp, cp2) {
        CORE_NP_GET_CP_MSGQ(cp, &msgq);
        while (!msgqueue_get_ds_read_buf(msgq, (unsigned char **)&hdr, &len)) {
            lune_assert((hdr->len + sizeof(coproc_resp_hdr_t)) == len);
            switch (hdr->type) {
#ifdef LUNE_BUILD_SSL
            case COPROC_RESP_TYPE_SSL:
            {
                int err;

                if (0 != (err = ossl_handle_coproc_resp(
                    (const unsigned char *)hdr->val, hdr->len))) {
                    lune_log(LUNE_INFO, "failed to handle ssl coprocessing response "
                        "on core %s: %s", CORE_GET_NAME(), ERR_GET_ERR_STR(err));
                }
                break;
            }
#endif
            default:
                break;
            }
            msgqueue_ds_read_buf_done(msgq);
        }
    }
}

int coproc_local_init(void)
{
    int err;
    coproc_t *cpi;

    lune_assert(CORE_IS_CP());
    lune_assert(NULL != (cpi = CORE_GET_CP_INFO()));

    if (NULL == (cpi->msgq_arrlist = arrlist_create_s_list(CORE_GET_NAME(),
        COPROC_MAX_CORES,
        sizeof(msgqueue_bd_t *)))) {
        lune_log(LUNE_WARN, "failed to create array list %s: %s",
            CORE_GET_NAME(), ERR_GET_LAST_ERR_STR());
        err = ERR_GET_LAST_ERR();
        goto ERR_1;
    }

    if (LUNE_INVALID_ID == (s_coproc_task_id = sched_add_task("coproc req msg handler",
        (lune_task_func_t)coproc_handle_req,
        (void *)CORE_GET_CP_INFO(),
        SCHED_PRIO_NORMAL))) {
        err = ERR_GET_LAST_ERR();
        goto ERR_2;
    }

#ifdef LUNE_BUILD_SSL
    if (0 != (err = ossl_local_init())) {
        goto ERR_3;
    }
#endif

    g_coproc_curr_msgq = NULL;

    return 0;

#ifdef LUNE_BUILD_SSL
ERR_3:
    lune_assert(!sched_del_task(s_coproc_task_id));
    s_coproc_task_id = LUNE_INVALID_ID;
#endif

ERR_2:
    lune_assert(!arrlist_delete_s_list(cpi->msgq_arrlist));

ERR_1:
    return err;
}

void coproc_local_fini(void)
{
    coproc_t *cpi;

    lune_assert(CORE_IS_CP());
    lune_assert(NULL != (cpi = CORE_GET_CP_INFO()));
    lune_assert(NULL == g_coproc_curr_msgq);

    /* all NPs have been unbound to CP, safe to delete it */
    lune_assert(ARRLIST_IS_EMPTY(cpi->msgq_arrlist));
    lune_assert(!arrlist_delete_s_list(cpi->msgq_arrlist));
    cpi->msgq_arrlist = NULL;

    lune_assert(!pthread_spin_destroy(&cpi->lock));
}
