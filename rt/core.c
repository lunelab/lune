/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2024 Lune Reseau, Inc.
 */

#include "lune/id.h"
#include "lune/os/linux.h"
#include "lune/time.h"

#include "drv/init.h"
#include "err/err.h"
#include "kernel/init.h"
#include "kernel/sched.h"
#include "kernel/time.h"
#include "lib/init.h"
#include "lib/arrlist.h"
#include "log/log.h"
#include "mem/mem.h"
#include "net/init.h"
#include "nrt/nrt.h"
#include "res/cpu.h"
#include "rt/comm.h"
#include "rt/coproc.h"
#include "rt/core.h"

/* optimal value after tuning */
#define CORE_NA_DEFAULT_HZ                  (LUNE_DEFAULT_HZ * 2)
#define CORE_CP_DEFAULT_HZ                  (LUNE_DEFAULT_HZ * 2)

#define CORE_NRT_WAIT_RT_RESP_MAX_RETRIES   (5)
#define CORE_NRT_WAIT_RT_RESP_SLEEP_USEC    (500)

typedef struct _core_comm_get_core_opt_conf {
    lune_core_opt_en opt;
    void *opt_val;
    unsigned int opt_len;
} core_comm_get_core_opt_conf_t;

typedef struct _core_comm_set_core_opt_conf {
    lune_core_opt_en opt;
    const void *opt_val;
    unsigned int opt_len;
} core_comm_set_core_opt_conf_t;

__thread core_ins_t *g_core_ins = NULL;
core_ins_t g_core_ins_array[LUNE_MAX_CORE_NUM];

msgqueue_bd_t *core_get_coproc_msgqueue(unsigned int cp_idx)
{
    net_proc_bound_cp_t *cp;

    if (unlikely(NULL == (cp = ARRLIST_GET_ELEM_BY_IDX(
        g_core_ins->np.cp_arrlist, cp_idx)))) {
        return NULL;
    }

    return *(msgqueue_bd_t **)ARRLIST_GET_ELEM_BY_IDX(
        g_core_ins_array[cp->id].cp.msgq_arrlist, cp->msgq_idx);
}

unsigned char *core_get_coproc_req_buf(unsigned int cp_idx,
    unsigned int type, unsigned int len)
{
    msgqueue_bd_t *msgq = core_get_coproc_msgqueue(cp_idx);
    return coproc_get_req_buf(msgq, type, len);
}

void core_coproc_req_buf_done(unsigned int cp_idx)
{
    msgqueue_bd_t *msgq = core_get_coproc_msgqueue(cp_idx);
    coproc_req_buf_done(msgq);
}

static int core_unbind_all_cps(void);

int core_reload_conf(void)
{
    lune_assert(CORE_INS_STATE_RUNNING == g_core_ins->state);

    if (CORE_INS_RELOAD_CP_BOUND_ON(g_core_ins)) {
        lune_assert(CORE_IS_NP());
        lune_assert(CORE_IS_CP_BOUND());
        lune_assert(LUNE_INVALID_ID == g_core_ins->np.cp_task_id);

        if (LUNE_INVALID_ID == (g_core_ins->np.cp_task_id =
            sched_add_task("coproc resp msg handler",
                (lune_task_func_t)coproc_handle_resp, NULL, SCHED_PRIO_NORMAL))) {
            lune_log(LUNE_INFO, "failed to create task on core %s to handle message "
                "from CP(s)", CORE_GET_NAME());
            /* failed to reload it, untie all coprocessors and keep going */
            lune_assert(!core_unbind_all_cps());
        } else {
            CORE_INS_RELOAD_CP_BOUND_SET_OFF(g_core_ins);
        }
    }

    return 0;
}

int core_init(void)
{
    int i;

    for (i = 0; i < LUNE_MAX_CORE_NUM; i++) {
        g_core_ins_array[i].conf.id = i;
        g_core_ins_array[i].conf.type = LUNE_CORE_NONE;
        g_core_ins_array[i].state = CORE_INS_STATE_IDLE;
        g_core_ins_array[i].msgq = NULL;
        g_core_ins_array[i].reload_flags = 0;
        g_core_ins_array[i].exit_flag = 0;
        g_core_ins_array[i].err = 0;
    }

    return 0;
}

void core_fini(void)
{
    int i;
    unsigned int sleep_usecs = 1000;

    for (i = 0; i < LUNE_MAX_CORE_NUM; i++) {
        lune_assert(CORE_INS_STATE_STARTING != g_core_ins_array[i].state);
        if (CORE_INS_STATE_RUNNING == g_core_ins_array[i].state) {
            /* kill core gracefully by signaling core to exit */
            lune_assert(0 == g_core_ins_array[i].exit_flag);
            g_core_ins_array[i].exit_flag = 1;
            while (CORE_INS_STATE_IDLE != g_core_ins_array[i].state) {
                usleep(sleep_usecs);
            }
        }
    }
}

static cpu_core_type_en core_conv_type(lune_core_type_en type)
{
    switch (type) {
    case LUNE_CORE_NA:
        return CPU_CORE_RT_NA;
    case LUNE_CORE_NP:
        return CPU_CORE_RT_NP;
    case LUNE_CORE_CP:
        return CPU_CORE_RT_CP;
    default:
        lune_assert(0);
        return CPU_CORE_IDLE;
    }
}

static unsigned int core_get_default_hz(lune_core_type_en type)
{
    switch (type) {
    case LUNE_CORE_NA:
        return CORE_NA_DEFAULT_HZ;
    case LUNE_CORE_NP:
        return LUNE_DEFAULT_HZ;
    case LUNE_CORE_CP:
        return CORE_CP_DEFAULT_HZ;
    default:
        lune_assert(0);
        return 0;
    }
}

static void *core_run_core(void *arg)
{
    core_ins_t *ci = (core_ins_t *)arg;
    lune_core_conf_t *conf = &ci->conf;
    char mod_str[LUNE_MAX_SHORT_NAME_BUF_LEN];
    int err;
    cpu_core_type_en type;
    unsigned int hz;

    g_core_ins = ci;
    sprintf(mod_str, "%s: ", ci->name);

    type = core_conv_type(conf->type);
    if (0 != (err = cpu_set_affinity(conf->id, type))) {
        strcat(mod_str, "cpu");
        goto ERR_1;
    }

    /*
        DO NOT change the order of module initialization
    */
    if (0 != (err = mem_local_init())) {
        strcat(mod_str, "memory");
        goto ERR_2;
    }

    if (0 != (err = lib_local_init())) {
        strcat(mod_str, "library");
        goto ERR_3;
    }

    if (0 == conf->hz) {
        /* default hz */
        hz = core_get_default_hz(conf->type);
    } else {
        hz = conf->hz;
    }

    if (0 != (err = time_local_init(hz))) {
        strcat(mod_str, "time");
        goto ERR_4;
    }

    if (0 != (err = kernel_local_init())) {
        strcat(mod_str, "kernel");
        goto ERR_5;
    }

    if (0 != (err = nrt_local_init(conf->id))) {
        strcat(mod_str, "non-realtime thread");
        goto ERR_6;
    }

    if (0 != (err = log_local_init(conf->log_file, conf->log_level))) {
        strcat(mod_str, "log");
        goto ERR_7;
    }

    if (0 != (err = drv_local_init())) {
        strcat(mod_str, "driver");
        goto ERR_8;
    }

    switch (conf->type) {
    case LUNE_CORE_NP:
        if (0 != (err = net_proc_local_init())) {
            strcat(mod_str, "network processor");
            goto ERR_9;
        }

        if (0 != (err = comm_local_init())) {
            strcat(mod_str, "communication");
            goto ERR_10;
        }

        break;
    case LUNE_CORE_NA:
        if (0 != (err = net_aggr_local_init())) {
            strcat(mod_str, "network aggregator");
            goto ERR_9;
        }

        if (0 != (err = comm_local_init())) {
            strcat(mod_str, "communication");
            goto ERR_10;
        }

        break;
    case LUNE_CORE_CP:
        if (0 != (err = coproc_local_init())) {
            strcat(mod_str, "coprocessor");
            goto ERR_9;
        }
        break;
    default:
        break;
    }

    if (NULL != conf->task.init
        && 0 != (err = conf->task.init(conf->task.data))) {
        strcat(mod_str, conf->task.name);
        goto ERR_11;
    }

    /* initialized, start running */
    ci->state = CORE_INS_STATE_RUNNING;

#ifdef LUNE_DEBUG
    if (0 != (err = mem_start_local_mem_stats_report())) {
        lune_log(LUNE_DBG, "failed to start reporting of memory statistics: %s", ERR_GET_LAST_ERR_STR());
        /* keep going */
    }
#endif

    if (LUNE_CORE_CP == conf->type) {
        sched_mini_loop();
    } else {
        sched_loop();
    }

    lune_assert(CORE_INS_STATE_QUITTING == ci->state);

#ifdef LUNE_DEBUG
    mem_stop_local_mem_stats_report();
#endif

    if (NULL != conf->task.fini) {
        conf->task.fini();
    }

    switch (conf->type) {
    case LUNE_CORE_NP:
        comm_local_fini();
        net_proc_local_fini();
        break;
    case LUNE_CORE_NA:
        comm_local_fini();
        net_aggr_local_fini();
        break;
    case LUNE_CORE_CP:
        coproc_local_fini();
        break;
    default:
        break;
    }

    drv_local_fini();
    log_local_fini();
    nrt_local_fini();
    kernel_local_fini();
    time_local_fini();
    lib_local_fini();
    mem_local_fini();

    /* release core */
    if (ci->exit_flag) {
        /* lune_delete_core() by another non-realtime core */
        ci->state = CORE_INS_STATE_IDLE;
    } else {
        /* lune_exit() by itself */
        ci->state = CORE_INS_STATE_QUITTED;
    }

    cpu_clear_affinity(conf->id);
    return NULL;

ERR_11:
    switch (conf->type) {
    case LUNE_CORE_NP:
        comm_local_fini();
        break;
    case LUNE_CORE_NA:
        comm_local_fini();
        break;
    default:
        break;
    }

ERR_10:
    switch (conf->type) {
    case LUNE_CORE_NP:
        net_proc_local_fini();
        break;
    case LUNE_CORE_NA:
        net_aggr_local_fini();
        break;
    case LUNE_CORE_CP:
        coproc_local_fini();
        break;
    default:
        break;
    }

ERR_9:
    drv_local_fini();

ERR_8:
    log_local_fini();

ERR_7:
    nrt_local_fini();

ERR_6:
    kernel_local_fini();

ERR_5:
    time_local_fini();

ERR_4:
    lib_local_fini();

ERR_3:
    mem_local_fini();

ERR_2:
    cpu_clear_affinity(conf->id);

ERR_1:
    lune_log(LUNE_INFO, "%s init failed: %s", mod_str, ERR_GET_ERR_STR(err));

    /* notify main thread that lune core failed to initialize */
    ci->err = err;
    ci->state = CORE_INS_STATE_IDLE;

    return NULL;
}

int lune_is_core_running(unsigned int id)
{
    if (unlikely(CORE_IS_RT_CORE())) {
        return ERR_SET_ERR(LUNE_ERR_NOT_SUPPORTED);
    }

    if (unlikely(!CPU_IS_VALID_CPU_ID(id))) {
        return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
    }

    return (CORE_INS_STATE_RUNNING == g_core_ins_array[id].state);
}

int lune_send_req_to_core(unsigned int id, const unsigned char *buf, unsigned int len)
{
    core_ins_t *ci;

    if (unlikely(CORE_IS_RT_CORE())) {
        return ERR_SET_ERR(LUNE_ERR_NOT_SUPPORTED);
    }

    if (unlikely(!CPU_IS_VALID_CPU_ID(id)
        || NULL == buf || 0 == len)) {
        return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
    }

    ci = &g_core_ins_array[id];
    switch (ci->state) {
    case CORE_INS_STATE_IDLE:
        return ERR_SET_ERR(LUNE_ERR_ID_NOT_FOUND);
    case CORE_INS_STATE_STARTING:
        return ERR_SET_ERR(LUNE_ERR_CORE_NOT_RUNNING);
    case CORE_INS_STATE_RUNNING:
        break;
    case CORE_INS_STATE_QUITTED:
        return ERR_SET_ERR(LUNE_ERR_CORE_ALREADY_EXIT);
    case CORE_INS_STATE_QUITTING:
        if (ci->exit_flag) {
            return ERR_SET_ERR(LUNE_ERR_ID_NOT_FOUND);
        } else {
            return ERR_SET_ERR(LUNE_ERR_CORE_ALREADY_EXIT);
        }
    default:
        return ERR_SET_ERR(LUNE_ERR_CORE_INTERNAL);
    }

    return comm_send_req_to_core(id, LUNE_COMM_REQ_APP, buf, len);
}

int lune_core_send_resp(const unsigned char *buf, unsigned int len, int err)
{
    if (unlikely(!CORE_IS_RT_CORE())) {
        return ERR_SET_ERR(LUNE_ERR_NOT_SUPPORTED);
    }

    if (unlikely(NULL == buf || 0 == len)) {
        return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
    }

    if (unlikely(CORE_INS_STATE_RUNNING != g_core_ins->state)) {
        if (CORE_INS_STATE_QUITTING == g_core_ins->state) {
            return ERR_SET_ERR(LUNE_ERR_CORE_ALREADY_EXIT);
        } else {
            lune_assert(CORE_INS_STATE_STARTING == g_core_ins->state);
            return ERR_SET_ERR(LUNE_ERR_CORE_NOT_RUNNING);
        }
    }

    return comm_core_send_resp(LUNE_COMM_RESP_APP, buf, len, err);
}

int lune_recv_resp_from_core(unsigned int id, unsigned char *pbuf, unsigned int *plen, int *perr)
{
    core_ins_t *ci;
    int err, retries = 0;
    lune_comm_resp_type_en resp_type;
    unsigned int sleep_usecs = CORE_NRT_WAIT_RT_RESP_SLEEP_USEC;

    if (unlikely(CORE_IS_RT_CORE())) {
        return ERR_SET_ERR(LUNE_ERR_NOT_SUPPORTED);
    }

    if (unlikely(!CPU_IS_VALID_CPU_ID(id) || NULL == plen || NULL == perr)) {
        return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
    }

    ci = &g_core_ins_array[id];
    switch (ci->state) {
    case CORE_INS_STATE_IDLE:
        return ERR_SET_ERR(LUNE_ERR_ID_NOT_FOUND);
    case CORE_INS_STATE_STARTING:
        return ERR_SET_ERR(LUNE_ERR_CORE_NOT_RUNNING);
    case CORE_INS_STATE_RUNNING:
        break;
    case CORE_INS_STATE_QUITTED:
        return ERR_SET_ERR(LUNE_ERR_CORE_ALREADY_EXIT);
    case CORE_INS_STATE_QUITTING:
        if (ci->exit_flag) {
            return ERR_SET_ERR(LUNE_ERR_ID_NOT_FOUND);
        } else {
            return ERR_SET_ERR(LUNE_ERR_CORE_ALREADY_EXIT);
        }
    default:
        return ERR_SET_ERR(LUNE_ERR_CORE_INTERNAL);
    }

    while (-LUNE_ERR_BUF_EMPTY == (err = comm_recv_resp_from_core(id,
        &resp_type, perr, pbuf, plen))
        && CORE_NRT_WAIT_RT_RESP_MAX_RETRIES >= ++retries) {
        usleep(sleep_usecs);
    }

    if (0 != err) {
        /* failed to receive response */
        if (CORE_NRT_WAIT_RT_RESP_MAX_RETRIES < retries) {
            lune_assert(-LUNE_ERR_BUF_EMPTY == err);
            return ERR_SET_ERR(LUNE_ERR_MAX_RETRIES);
        }

        return err;
    }

    if (LUNE_COMM_RESP_APP != resp_type) {
        /* unexpected response */
        return ERR_SET_ERR(LUNE_ERR_APP_INTERNAL);
    }

    if (0 != *perr) {
        /* set error on current non-runtime core */
        ERR_SET_ERR(-*perr);
    }

    return 0;
}

int lune_create_core(lune_core_conf_t *conf)
{
    unsigned int sleep_usecs = 1000;
    core_ins_t *ci;

    if (unlikely(CORE_IS_RT_CORE())) {
        return ERR_SET_ERR(LUNE_ERR_NOT_SUPPORTED);
    }

    if (NULL == conf
        || !CPU_IS_VALID_CPU_ID(conf->id)
        || conf->type < LUNE_CORE_NA
        || conf->type >= LUNE_CORE_NONE
        || (conf->hz < LUNE_MIN_HZ && conf->hz != 0)
        || conf->hz > LUNE_MAX_HZ
        || (conf->hz % LUNE_MIN_HZ) != 0
        || conf->log_level < LUNE_CRIT
        || conf->log_level >= LUNE_LOG_LEVEL_NUM) {
        ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        goto ERR_1;
    }

    ci = &g_core_ins_array[conf->id];

    if (CORE_INS_STATE_IDLE != ci->state) {
        ERR_SET_ERR(LUNE_ERR_ALREADY_EXIST);
        goto ERR_1;
    }

    ci->state = CORE_INS_STATE_STARTING;

    lune_assert(NULL == ci->msgq);

    sprintf(ci->name, "lc%d", conf->id);

    if (NULL == (ci->msgq = msgqueue_create_bd_queue(ci->name,
        CORE_INS_MSGQ_SIZE, CORE_INS_MSGQ_SIZE))) {
        lune_log(LUNE_WARN, "failed to create msg queue %s: %s", ci->name, ERR_GET_LAST_ERR_STR());
        goto ERR_2;
    }

    lune_assert(ci->conf.id == conf->id);
    ci->conf.type = conf->type;
    ci->conf.hz = conf->hz;
    ci->conf.log_level = conf->log_level;
    strcpy(ci->conf.log_file, conf->log_file);
    ci->conf.task.init = conf->task.init;
    ci->conf.task.fini = conf->task.fini;
    ci->conf.task.data = conf->task.data;
    strcpy(ci->conf.task.name, conf->task.name);

    switch (ci->conf.type) {
    case LUNE_CORE_NP:
        ci->np.cp_arrlist = NULL;
        ci->np.cp_task_id = LUNE_INVALID_ID;
        break;
    case LUNE_CORE_CP:
        ci->cp.msgq_arrlist = NULL;
        ci->cp.core_num = 0;
        pthread_spin_init(&ci->cp.lock, PTHREAD_PROCESS_PRIVATE);
        break;
    default:
        break;
    }

    ci->reload_flags = 0;
    ci->exit_flag = 0;
    ci->err = 0;

    if (lune_create_thread(&ci->tid, ci->name, core_run_core, (void *)ci)) {
        lune_log(LUNE_WARN, "failed to create lune core %s: %s", ci->name, strerror(errno));
        ERR_SET_ERR(LUNE_ERR_SYS_ERR);
        goto ERR_3;
    }

    while (CORE_INS_STATE_STARTING == ci->state) {
        /* sleep till thread is running, or quitting due to failure or short lifespan */
        usleep(sleep_usecs);
    }

    if (CORE_INS_STATE_RUNNING != ci->state) {
        if (0 == ci->err) {
            while (CORE_INS_STATE_QUITTING == ci->state) {
                /* core itself exiting (by calling lune_exit()) */
                usleep(sleep_usecs);
            }
            lune_assert(CORE_INS_STATE_QUITTED == ci->state);
            lune_log(LUNE_INFO, "lune core %s already exited", ci->name);
            ERR_SET_ERR(LUNE_ERR_CORE_ALREADY_EXIT);
        } else {
            /* failed to run */
            lune_assert(ci->err < 0);
            lune_assert(CORE_INS_STATE_IDLE == ci->state);
            lune_log(LUNE_WARN, "failed to run lune core %s: %s",
                ci->name, ERR_GET_ERR_STR(ERR_SET_ERR(-ci->err)));
        }
        goto ERR_3;
    }

    /* use core id as id */
    return conf->id;

ERR_3:
    switch (ci->conf.type) {
    case LUNE_CORE_CP:
        pthread_spin_destroy(&ci->cp.lock);
        break;
    default:
        break;
    }

    ci->conf.type = LUNE_CORE_NONE;

    msgqueue_delete_bd_queue(ci->msgq);
    ci->msgq = NULL;

ERR_2:
    ci->state = CORE_INS_STATE_IDLE;

ERR_1:
    return ERR_GET_LAST_ERR();
}

static int core_unbind_all_cps(void)
{
    void *n, *n2;
    unsigned int cp_idx;
    msgqueue_bd_t *msgq;

    ARRLIST_FOR_EACH_NODE_SAFE(g_core_ins->np.cp_arrlist, n, n2) {
        cp_idx = ARRLIST_GET_NODE_IDX(n);
        msgq = core_get_coproc_msgqueue(cp_idx);
        if (NULL == coproc_get_req_buf(msgq, COPROC_REQ_TYPE_KILL, 0)) {
            return ERR_GET_LAST_ERR();
        }

        coproc_req_buf_done(msgq);

        arrlist_s_list_free_elem(g_core_ins->np.cp_arrlist, ARRLIST_GET_ELEM_BY_NODE(n));
    }

    if (LUNE_INVALID_ID != g_core_ins->np.cp_task_id) {
        lune_assert(!sched_del_task(g_core_ins->np.cp_task_id));
        g_core_ins->np.cp_task_id = LUNE_INVALID_ID;
    } else {
        /* CP configuration has yet to be reloaded on current core */
#ifdef LUNE_DEBUG
        lune_assert(CORE_INS_RELOAD_CP_BOUND_ON(g_core_ins));
#endif
        CORE_INS_RELOAD_CP_BOUND_SET_OFF(g_core_ins);
    }

    lune_assert(!arrlist_delete_s_list(g_core_ins->np.cp_arrlist));
    g_core_ins->np.cp_arrlist = NULL;

    return 0;
}

int core_cleanup_core(void)
{
    if (CORE_IS_CP_BOUND()) {
        return core_unbind_all_cps();
    } else if (CORE_IS_CP()) {
        return coproc_cleanup_core();
    }

    return 0;
}

int lune_delete_core(unsigned int id)
{
    core_ins_t *ci;
    unsigned int sleep_usecs = 1000;

    if (unlikely(CORE_IS_RT_CORE())) {
        return ERR_SET_ERR(LUNE_ERR_NOT_SUPPORTED);
    }

    if (!CPU_IS_VALID_CPU_ID(id)) {
        return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
    }

    ci = &g_core_ins_array[id];

    if (LUNE_CORE_CP == ci->conf.type) {
        pthread_spin_lock(&ci->cp.lock);
        if (0 != ci->cp.core_num) {
            /* untie all NPs first */
            pthread_spin_unlock(&ci->cp.lock);
            return ERR_SET_ERR(LUNE_ERR_NOT_READY);
        }

        ci->cp.core_num = (unsigned int)-1;
        pthread_spin_unlock(&ci->cp.lock);
    }

    switch (ci->state) {
    case CORE_INS_STATE_RUNNING:
        break;
    case CORE_INS_STATE_QUITTED:
        /* core itself exited (by calling lune_exit()) */
        lune_log(LUNE_INFO, "lune core %s already exited", ci->name);
        lune_assert(0 == ci->exit_flag);
        ci->state = CORE_INS_STATE_IDLE;
        break;
    case CORE_INS_STATE_QUITTING:
        if (ci->exit_flag) {
            /* lune_delete_core() already called */
            return ERR_SET_ERR(LUNE_ERR_ID_NOT_FOUND);
        }

        /* core itself exiting (by calling lune_exit()), wait until it quits */
        lune_log(LUNE_INFO, "lune core %s exiting", ci->name);
        while (CORE_INS_STATE_QUITTED != ci->state) {
            usleep(sleep_usecs);
        }
        ci->state = CORE_INS_STATE_IDLE;
        break;
    case CORE_INS_STATE_IDLE:
        return ERR_SET_ERR(LUNE_ERR_ID_NOT_FOUND);
    default:
        return ERR_SET_ERR(LUNE_ERR_CORE_INTERNAL);
    }

    /* kill core gracefully by signaling core to exit */
    ci->exit_flag = 1;

    while (CORE_INS_STATE_IDLE != ci->state) {
        usleep(sleep_usecs);
    }

    ci->conf.type = LUNE_CORE_NONE;

    msgqueue_delete_bd_queue(ci->msgq);
    ci->msgq = NULL;

    return 0;
}

static int core_nrt_get_core_opt(unsigned int id,
    lune_core_opt_en opt, unsigned char *opt_val, unsigned int opt_len)
{
    unsigned int sleep_usecs = CORE_NRT_WAIT_RT_RESP_SLEEP_USEC;
    lune_comm_resp_type_en resp_type;
    int err, rt_err = 0;
    core_comm_get_core_opt_conf_t conf;

    lune_assert(!CORE_IS_RT_CORE());

    conf.opt = opt;
    conf.opt_val = opt_val;
    conf.opt_len = opt_len;
    if (0 != (err = comm_send_req_to_core(id,
        LUNE_COMM_REQ_GET_CORE_OPT,
        (const void *)&conf,
        sizeof(conf)))) {
        lune_log(LUNE_INFO, "failed to send request of getting option %d"
            " of core %d: %s", opt, id, ERR_GET_ERR_STR(err));
        return err;
    }

    while (-LUNE_ERR_BUF_EMPTY == (err = comm_recv_resp_from_core(id,
        &resp_type, &rt_err, NULL, 0))) {
        usleep(sleep_usecs);
    }

    if (0 != rt_err) {
        lune_assert(0 == err);
        err = rt_err;
        ERR_SET_ERR(-err);
    }

    if (0 != err) {
        lune_log(LUNE_INFO, "failed to get option %d of core %d: %s",
            opt, id, ERR_GET_ERR_STR(err));
        return err;
    }

    lune_assert(LUNE_COMM_RESP_GET_CORE_OPT == resp_type);

    return 0;
}

int lune_get_core_opt(unsigned int id,
    lune_core_opt_en opt, unsigned char *opt_val, unsigned int opt_len)
{
    if (unlikely(!CPU_IS_VALID_CPU_ID(id)
        || NULL == opt_val || 0 == opt_len)) {
        return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
    }

    if (unlikely(CORE_IS_RT_CORE())) {
        return ERR_SET_ERR(LUNE_ERR_NOT_SUPPORTED);
    }

    return core_nrt_get_core_opt(id, opt, opt_val, opt_len);
}

static unsigned int core_get_avail_cp_msgq_idx(coproc_t *cp)
{
    msgqueue_bd_t **msgq;

    if (NULL == (msgq = arrlist_s_list_alloc_elem(cp->msgq_arrlist))) {
        return COPROC_MAX_CORES;
    }

    *msgq = NULL;
    return ARRLIST_GET_ELEM_IDX(msgq);
}

static msgqueue_bd_t **core_get_cp_msgq(coproc_t *cp, unsigned int msgq_idx)
{
    return (msgqueue_bd_t **)ARRLIST_GET_ELEM_BY_IDX(cp->msgq_arrlist, msgq_idx);
}

static int core_bind_cp(unsigned int cp_id)
{
    core_ins_t *cp_ci;
    net_proc_bound_cp_t *cp;
    msgqueue_bd_t **msgq;
    void *n;

    cp_ci = &g_core_ins_array[cp_id];
    if (cp_ci->conf.type != LUNE_CORE_CP) {
        ERR_SET_ERR(LUNE_ERR_NOT_SUPPORTED);
        goto ERR_1;
    }

    if (unlikely(CORE_INS_STATE_RUNNING != cp_ci->state)) {
        ERR_SET_ERR(LUNE_ERR_CORE_NOT_RUNNING);
        goto ERR_1;
    }

    pthread_spin_lock(&cp_ci->cp.lock);
    if (COPROC_MAX_CORES == cp_ci->cp.core_num) {
        ERR_SET_ERR(LUNE_ERR_EXCEED_LIMITS);
        goto ERR_2;
    } else if (COPROC_MAX_CORES < cp_ci->cp.core_num) {
        /* tie a CP that was just being deleted */
        lune_assert((unsigned int)-1 == cp_ci->cp.core_num);
        ERR_SET_ERR(LUNE_ERR_ALREADY_DELETED);
        goto ERR_2;
    }

    if (NULL == g_core_ins->np.cp_arrlist
        && (NULL == (g_core_ins->np.cp_arrlist =
            arrlist_create_s_list(g_core_ins->name,
                CORE_NP_MAX_BOUND_CP_NUM,
                sizeof(net_proc_bound_cp_t))))) {
        goto ERR_2;
    }

    ARRLIST_FOR_EACH_NODE(g_core_ins->np.cp_arrlist, n) {
        cp = ARRLIST_GET_ELEM_BY_NODE(n);
        if (cp->id == cp_id) {
            ERR_SET_ERR(LUNE_ERR_ALREADY_BOUND);
            goto ERR_3;
        }
    }

    if (NULL == (cp = arrlist_s_list_alloc_elem(g_core_ins->np.cp_arrlist))) {
        goto ERR_3;
    }

    cp->id = cp_id;
    cp->msgq_idx = core_get_avail_cp_msgq_idx(&cp_ci->cp);
    if (COPROC_MAX_CORES == cp->msgq_idx) {
        ERR_SET_ERR(LUNE_ERR_EXCEED_LIMITS);
        goto ERR_4;
    }

    msgq = core_get_cp_msgq(&cp_ci->cp, cp->msgq_idx);
    if (NULL == (*msgq = msgqueue_create_bd_queue(g_core_ins->name,
        COPROC_MSGQ_SIZE, COPROC_MSGQ_SIZE))) {
        goto ERR_4;
    }

    cp_ci->cp.core_num++;
    pthread_spin_unlock(&cp_ci->cp.lock);

    if (LUNE_INVALID_ID == g_core_ins->np.cp_task_id
        && !CORE_INS_RELOAD_CP_BOUND_ON(g_core_ins)) {
        /* to trigger reloading of CP configuration on current core */
        CORE_INS_RELOAD_CP_BOUND_SET_ON(g_core_ins);
    }

    return 0;

ERR_4:
    arrlist_s_list_free_elem(g_core_ins->np.cp_arrlist, cp);

ERR_3:
    if (ARRLIST_IS_EMPTY(g_core_ins->np.cp_arrlist)) {
        /* array list just created */
        lune_assert(LUNE_INVALID_ID == g_core_ins->np.cp_task_id);
        lune_assert(!CORE_INS_RELOAD_CP_BOUND_ON(g_core_ins));
        lune_assert(!arrlist_delete_s_list(g_core_ins->np.cp_arrlist));
        g_core_ins->np.cp_arrlist = NULL;
    }

ERR_2:
    pthread_spin_unlock(&cp_ci->cp.lock);

ERR_1:
    return ERR_GET_LAST_ERR();
}

static int core_unbind_cp(unsigned int cp_id)
{
    core_ins_t *cp_ci;
    net_proc_bound_cp_t *cp;
    void *n, *n2;
    unsigned int found;
    msgqueue_bd_t *msgq;

    cp_ci = &g_core_ins_array[cp_id];
    if (cp_ci->conf.type != LUNE_CORE_CP) {
        ERR_SET_ERR(LUNE_ERR_NOT_SUPPORTED);
        goto ERR_1;
    }

    if (unlikely(CORE_INS_STATE_RUNNING != cp_ci->state)) {
        ERR_SET_ERR(LUNE_ERR_CORE_NOT_RUNNING);
        goto ERR_1;
    }

    found = 0;
    cp = NULL;
    ARRLIST_FOR_EACH_NODE_SAFE(g_core_ins->np.cp_arrlist, n, n2) {
        cp = (net_proc_bound_cp_t *)ARRLIST_GET_ELEM_BY_NODE(n);
        if (cp->id == cp_id) {
            found = 1;
            break;
        }
    }

    if (!found) {
        ERR_SET_ERR(LUNE_ERR_ID_NOT_FOUND);
        goto ERR_1;
    }

    lune_assert(NULL != cp);
    msgq = core_get_coproc_msgqueue(ARRLIST_GET_ELEM_IDX(cp));
    if (NULL == coproc_get_req_buf(msgq, COPROC_REQ_TYPE_KILL, 0)) {
        goto ERR_1;
    }

    coproc_req_buf_done(msgq);

    arrlist_s_list_free_elem(g_core_ins->np.cp_arrlist, cp);
    if (ARRLIST_IS_EMPTY(g_core_ins->np.cp_arrlist)) {
        if (LUNE_INVALID_ID != g_core_ins->np.cp_task_id) {
            lune_assert(!sched_del_task(g_core_ins->np.cp_task_id));
            g_core_ins->np.cp_task_id = LUNE_INVALID_ID;
        } else {
            /* CP configuration has yet to be reloaded on current core */
#ifdef LUNE_DEBUG
            lune_assert(CORE_INS_RELOAD_CP_BOUND_ON(g_core_ins));
#endif
            CORE_INS_RELOAD_CP_BOUND_SET_OFF(g_core_ins);
        }

        lune_assert(!arrlist_delete_s_list(g_core_ins->np.cp_arrlist));
        g_core_ins->np.cp_arrlist = NULL;
    }

    return 0;

ERR_1:
    return ERR_GET_LAST_ERR();
}

static int core_nrt_set_core_opt(unsigned int id,
    lune_core_opt_en opt, const unsigned char *opt_val, unsigned int opt_len)
{
    unsigned int sleep_usecs = CORE_NRT_WAIT_RT_RESP_SLEEP_USEC;
    lune_comm_resp_type_en resp_type;
    int err, rt_err = 0;
    core_comm_set_core_opt_conf_t conf;

    lune_assert(!CORE_IS_RT_CORE());

    conf.opt = opt;
    conf.opt_val = opt_val;
    conf.opt_len = opt_len;
    if (0 != (err = comm_send_req_to_core(id,
        LUNE_COMM_REQ_SET_CORE_OPT,
        (const void *)&conf,
        sizeof(conf)))) {
        lune_log(LUNE_INFO, "failed to send request of setting option %d"
            " of core %d: %s", opt, id, ERR_GET_ERR_STR(err));
        return err;
    }

    while (-LUNE_ERR_BUF_EMPTY == (err = comm_recv_resp_from_core(id,
        &resp_type, &rt_err, NULL, 0))) {
        usleep(sleep_usecs);
    }

    if (0 != rt_err) {
        lune_assert(0 == err);
        err = rt_err;
        ERR_SET_ERR(-err);
    }

    if (0 != err) {
        lune_log(LUNE_INFO, "failed to set option %d of core %d: %s",
            opt, id, ERR_GET_ERR_STR(err));
        return err;
    }

    lune_assert(LUNE_COMM_RESP_SET_CORE_OPT == resp_type);

    return 0;
}

int lune_set_core_opt(unsigned int id,
    lune_core_opt_en opt, const unsigned char *opt_val, unsigned int opt_len)
{
    if (unlikely(!CPU_IS_VALID_CPU_ID(id))) {
        return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
    }

    if (unlikely(CORE_IS_RT_CORE())) {
        return ERR_SET_ERR(LUNE_ERR_NOT_SUPPORTED);
    }

    return core_nrt_set_core_opt(id, opt, opt_val, opt_len);
}

int lune_core_get_opt(lune_core_opt_en opt, unsigned char *opt_val, unsigned int opt_len)
{
    if (unlikely(!CORE_IS_RT_CORE())) {
        return ERR_SET_ERR(LUNE_ERR_NOT_SUPPORTED);
    }

    if (NULL == opt_val || 0 == opt_len) {
        return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
    }

    switch (opt) {
    case LUNE_CORE_OPT_GET_TYPE:
        if (opt_len != sizeof(lune_core_type_en)) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        *(lune_core_type_en *)opt_val = g_core_ins->conf.type;
        break;
    default:
        return ERR_SET_ERR(LUNE_ERR_OPT_NOT_FOUND);
    }

    return 0;
}

int lune_core_set_opt(lune_core_opt_en opt, const unsigned char *opt_val, unsigned int opt_len)
{
    if (unlikely(!CORE_IS_RT_CORE())) {
        return ERR_SET_ERR(LUNE_ERR_NOT_SUPPORTED);
    }

    switch (opt) {
    case LUNE_CORE_OPT_BIND_CP:
        if (unlikely(NULL == opt_val
            || opt_len != (sizeof(unsigned int))
            || !CPU_IS_VALID_CPU_ID(*(const unsigned int *)opt_val))) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        if (unlikely(!CORE_IS_NP())) {
            /* CP binding only supported with NP so far */
            return ERR_SET_ERR(LUNE_ERR_CORE_TYPE_ERR);
        }

        if (unlikely(CORE_INS_STATE_RUNNING != g_core_ins->state)) {
            return ERR_SET_ERR(LUNE_ERR_CORE_NOT_RUNNING);
        }

        return core_bind_cp(*(const unsigned int *)opt_val);
    case LUNE_CORE_OPT_UNBIND_CP:
        if (unlikely(NULL == opt_val
            || opt_len != (sizeof(unsigned int))
            || !CPU_IS_VALID_CPU_ID(*(const unsigned int *)opt_val))) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        if (unlikely(!CORE_IS_NP())) {
            /* CP binding only supported with NP so far */
            return ERR_SET_ERR(LUNE_ERR_CORE_TYPE_ERR);
        }

        if (unlikely(CORE_INS_STATE_RUNNING != g_core_ins->state)) {
            return ERR_SET_ERR(LUNE_ERR_CORE_NOT_RUNNING);
        }

        return core_unbind_cp(*(const unsigned int *)opt_val);
    case LUNE_CORE_OPT_UNBIND_ALL_CPS:
        if (unlikely(NULL != opt_val || 0 != opt_len)) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        if (unlikely(!CORE_IS_NP())) {
            /* CP binding only supported with NP so far */
            return ERR_SET_ERR(LUNE_ERR_CORE_TYPE_ERR);
        }

        if (unlikely(CORE_INS_STATE_RUNNING != g_core_ins->state)) {
            return ERR_SET_ERR(LUNE_ERR_CORE_NOT_RUNNING);
        }

        if (!CORE_IS_CP_BOUND()) {
            return ERR_SET_ERR(LUNE_ERR_CORE_UNBOUND);
        }

        return core_unbind_all_cps();
    case LUNE_CORE_OPT_SET_LOG_CPU_USAGE_OFF:
        LOG_SET_CPU_USAGE_OFF();
        return 0;
    case LUNE_CORE_OPT_SET_LOG_CPU_USAGE_ON:
        LOG_SET_CPU_USAGE_ON();
        return 0;
    default:
        return ERR_SET_ERR(LUNE_ERR_OPT_NOT_FOUND);
    }
}

int lune_core_get_id(void)
{
    if (unlikely(NULL == g_core_ins)) {
        return ERR_SET_ERR(LUNE_ERR_ID_NOT_FOUND);
    }

    return CORE_GET_ID();
}

unsigned int core_get_next_bound_cp_idx(void)
{
    net_proc_bound_cp_t *cp;

    if (unlikely(NULL == g_core_ins->np.cp_arrlist)) {
        return CORE_NP_MAX_BOUND_CP_NUM;
    }

    lune_assert(NULL != (cp = arrlist_s_list_get_next_elem(g_core_ins->np.cp_arrlist)));

    return ARRLIST_GET_ELEM_IDX(cp);
}

unsigned char *core_get_core_req_send_buf(unsigned int id, unsigned int len)
{
    unsigned char *p;
    if (NULL == (p = msgqueue_get_us_write_buf(g_core_ins_array[id].msgq, len))) {
        ERR_SET_ERR(LUNE_ERR_BUF_FULL);
    }

    return p;
}

void core_req_send_buf_done(unsigned int id)
{
    msgqueue_us_write_buf_done(g_core_ins_array[id].msgq);
}

int core_get_core_req_recv_buf(unsigned char **pbuf, unsigned int *plen)
{
    return msgqueue_get_us_read_buf(g_core_ins->msgq, pbuf, plen);
}

void core_req_recv_buf_done(void)
{
    msgqueue_us_read_buf_done(g_core_ins->msgq);
}

int core_get_core_resp_recv_buf(unsigned int id, unsigned char **pbuf, unsigned int *plen)
{
    return msgqueue_get_ds_read_buf(g_core_ins_array[id].msgq, pbuf, plen);
}

void core_resp_recv_buf_done(unsigned int id)
{
    msgqueue_ds_read_buf_done(g_core_ins_array[id].msgq);
}

unsigned char *core_get_core_resp_send_buf(unsigned int len)
{
    unsigned char *p;
    if (NULL == (p = msgqueue_get_ds_write_buf(g_core_ins->msgq, len))) {
        ERR_SET_ERR(LUNE_ERR_BUF_FULL);
    }

    return p;
}

void core_resp_send_buf_done(void)
{
    msgqueue_ds_write_buf_done(g_core_ins->msgq);
}

static void core_handle_comm_req_get_core_opt(const void *val, unsigned int len)
{
    int err;
    const core_comm_get_core_opt_conf_t *conf;

    if (unlikely(NULL == val || len != sizeof(core_comm_get_core_opt_conf_t))) {
        err = ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        lune_log(LUNE_INFO, "failed to get option of core: %s",
            ERR_GET_ERR_STR(err));
        if (0 != (err = comm_core_send_resp(LUNE_COMM_RESP_GET_CORE_OPT, NULL, 0, err))) {
            lune_log(LUNE_INFO, "failed to send response to get option of core: %s",
                ERR_GET_ERR_STR(err));
        }
        return;
    }

    conf = (const core_comm_get_core_opt_conf_t *)val;
    if (0 != (err = lune_core_get_opt(conf->opt, conf->opt_val, conf->opt_len))) {
        err = ERR_GET_LAST_ERR();
        lune_log(LUNE_INFO, "failed to get option %d of core %d: %s",
            conf->opt, CORE_GET_ID(), ERR_GET_ERR_STR(err));
        goto ERR;
    }

    if (0 != (err = comm_core_send_resp(LUNE_COMM_RESP_GET_CORE_OPT, NULL, 0, err))) {
        lune_log(LUNE_INFO, "failed to send response to get option %d of core %d: %s",
            conf->opt, CORE_GET_ID(), ERR_GET_ERR_STR(err));
    }

    return;

ERR:
    if (0 != (err = comm_core_send_resp(LUNE_COMM_RESP_GET_CORE_OPT, NULL, 0, err))) {
        lune_log(LUNE_INFO, "failed to send response to get option %d of core %d: %s",
            conf->opt, CORE_GET_ID(), ERR_GET_ERR_STR(err));
    }
}

static void core_handle_comm_req_set_core_opt(const void *val, unsigned int len)
{
    int err;
    const core_comm_set_core_opt_conf_t *conf;

    if (unlikely(NULL == val || len != sizeof(core_comm_set_core_opt_conf_t))) {
        err = ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        lune_log(LUNE_INFO, "failed to set option of core: %s",
            ERR_GET_ERR_STR(err));
        if (0 != (err = comm_core_send_resp(LUNE_COMM_RESP_SET_CORE_OPT, NULL, 0, err))) {
            lune_log(LUNE_INFO, "failed to send response to set option of core: %s",
                ERR_GET_ERR_STR(err));
        }
    }

    conf = (const core_comm_set_core_opt_conf_t *)val;
    if (0 != (err = lune_core_set_opt(conf->opt, conf->opt_val, conf->opt_len))) {
        err = ERR_GET_LAST_ERR();
        lune_log(LUNE_INFO, "failed to set option %d of core %d: %s",
            conf->opt, CORE_GET_ID(), ERR_GET_ERR_STR(err));
        goto ERR;
    }

    if (0 != (err = comm_core_send_resp(LUNE_COMM_RESP_SET_CORE_OPT, NULL, 0, err))) {
        lune_log(LUNE_INFO, "failed to send response to set option %d of core %d: %s",
            conf->opt, CORE_GET_ID(), ERR_GET_ERR_STR(err));
    }

    return;

ERR:
    if (0 != (err = comm_core_send_resp(LUNE_COMM_RESP_SET_CORE_OPT, NULL, 0, err))) {
        lune_log(LUNE_INFO, "failed to send response to set option %d of core %d: %s",
            conf->opt, CORE_GET_ID(), ERR_GET_ERR_STR(err));
    }
}

COMM_REQ_HANDLER_DECL(GET_CORE_OPT, core_handle_comm_req_get_core_opt)
COMM_REQ_HANDLER_DECL(SET_CORE_OPT, core_handle_comm_req_set_core_opt)
