/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2024 Lune Reseau, Inc.
 */

#include "lune/assert.h"
#include "lune/core.h"
#include "lune/cpu.h"
#include "lune/err.h"
#include "lune/log.h"
#include "lune/os/linux.h"

#include "err/err.h"
#include "res/cpu.h"

static pthread_spinlock_t s_cpu_info_lock;
cpu_info_t g_cpu_info;

static __thread unsigned int s_cpu_curr_core_id;

unsigned int cpu_get_num_of_core_avail(void)
{
    return g_cpu_info.num_of_core_avail;
}

static inline cpu_set_t cpu_get_mask(unsigned int core_id)
{
    cpu_set_t mask;

    CPU_ZERO(&mask);
    CPU_SET(core_id, &mask);

    return mask;
}

int cpu_set_affinity(unsigned int core_id, cpu_core_type_en type)
{
    cpu_set_t mask;

    if (!CPU_IS_VALID_CPU_ID(core_id)) {
        return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
    }

    pthread_spin_lock(&s_cpu_info_lock);
    if (CPU_IS_BIT_SET(g_cpu_info.rt_na_core_occupied, core_id)
        || CPU_IS_BIT_SET(g_cpu_info.rt_np_core_occupied, core_id)
        || CPU_IS_BIT_SET(g_cpu_info.rt_cp_core_occupied, core_id)) {
        pthread_spin_unlock(&s_cpu_info_lock);
        return ERR_SET_ERR(LUNE_ERR_CORE_OCCUPIED);
    }

    mask = cpu_get_mask(core_id);
    if (0 != sched_setaffinity(0, sizeof(mask), &mask)) {
        pthread_spin_unlock(&s_cpu_info_lock);
        lune_log(LUNE_CRIT, "failed to set core %d (type %d) affinity: %s", core_id, type, strerror(errno));
        return ERR_SET_ERR(LUNE_ERR_SYS_ERR);
    }

    switch (type) {
    case CPU_CORE_NRT:
        /* NRT cpu may be bound to more than one thread */
        CPU_SET_BIT(g_cpu_info.nrt_core_occupied, core_id);
        break;
    case CPU_CORE_RT_NA:
        CPU_SET_BIT(g_cpu_info.rt_na_core_occupied, core_id);
        break;
    case CPU_CORE_RT_NP:
        CPU_SET_BIT(g_cpu_info.rt_np_core_occupied, core_id);
        break;
    case CPU_CORE_RT_CP:
        CPU_SET_BIT(g_cpu_info.rt_cp_core_occupied, core_id);
        break;
    default:
        pthread_spin_unlock(&s_cpu_info_lock);
        return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
    }

    pthread_spin_unlock(&s_cpu_info_lock);

    s_cpu_curr_core_id = core_id;
    return 0;
}

int cpu_clear_affinity(unsigned int core_id)
{
    if (!(CPU_IS_VALID_CPU_ID(core_id))) {
        return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
    }

    pthread_spin_lock(&s_cpu_info_lock);
    if (CPU_IS_BIT_SET(g_cpu_info.rt_na_core_occupied, core_id)) {
        CPU_CLEAR_BIT(g_cpu_info.rt_na_core_occupied, core_id);
    } else if (CPU_IS_BIT_SET(g_cpu_info.rt_np_core_occupied, core_id)) {
        CPU_CLEAR_BIT(g_cpu_info.rt_np_core_occupied, core_id);
    } else if (CPU_IS_BIT_SET(g_cpu_info.rt_cp_core_occupied, core_id)) {
        CPU_CLEAR_BIT(g_cpu_info.rt_cp_core_occupied, core_id);
    } else if (CPU_IS_BIT_SET(g_cpu_info.nrt_core_occupied, core_id)) {
        CPU_CLEAR_BIT(g_cpu_info.nrt_core_occupied, core_id);
    } else {
        pthread_spin_unlock(&s_cpu_info_lock);
        return ERR_SET_ERR(LUNE_ERR_CORE_UNOCCUPIED);
    }

    pthread_spin_unlock(&s_cpu_info_lock);
    return 0;
}

static int cpu_parse_cpu_list_scan_is_valid(int ret,
    char next_sym, const char *sym_range)
{
    if ((1 == ret || (2 == ret && NULL != strchr(sym_range, next_sym)))) {
        return 1;
    }

    return 0;
}

int cpu_get_core_bit_mask(cpu_bit_mask_t *bit_mask, cpu_core_type_en type)
{
    if (unlikely(NULL == bit_mask)) {
        return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
    }

    pthread_spin_lock(&s_cpu_info_lock);
    switch (type) {
    case CPU_CORE_NRT:
        *bit_mask = *bit_mask & g_cpu_info.nrt_core_occupied;
        break;
    case CPU_CORE_RT_NA:
        *bit_mask = *bit_mask & g_cpu_info.rt_na_core_occupied;
        break;
    case CPU_CORE_RT_NP:
        *bit_mask = *bit_mask & g_cpu_info.rt_np_core_occupied;
        break;
    case CPU_CORE_RT_CP:
        *bit_mask = *bit_mask & g_cpu_info.rt_cp_core_occupied;
        break;
    default:
        pthread_spin_unlock(&s_cpu_info_lock);
        return ERR_SET_ERR(LUNE_ERR_INTERNAL);
    }

    pthread_spin_unlock(&s_cpu_info_lock);
    return 0;
}

int cpu_get_first_core(cpu_bit_mask_t bit_mask, cpu_core_type_en type)
{
    unsigned int core_id;

    pthread_spin_lock(&s_cpu_info_lock);
    switch (type) {
    case CPU_CORE_NRT:
        bit_mask = bit_mask & g_cpu_info.nrt_core_occupied;
        break;
    case CPU_CORE_RT_NA:
        bit_mask = bit_mask & g_cpu_info.rt_na_core_occupied;
        break;
    case CPU_CORE_RT_NP:
        bit_mask = bit_mask & g_cpu_info.rt_np_core_occupied;
        break;
    case CPU_CORE_RT_CP:
        bit_mask = bit_mask & g_cpu_info.rt_cp_core_occupied;
        break;
    default:
        pthread_spin_unlock(&s_cpu_info_lock);
        return ERR_SET_ERR(LUNE_ERR_INTERNAL);
    }

    pthread_spin_unlock(&s_cpu_info_lock);

    core_id = 0;
    while (!CPU_IS_BIT_SET(bit_mask, core_id)
        && core_id < g_cpu_info.num_of_core_avail) {
        core_id++;
    }

    return core_id < g_cpu_info.num_of_core_avail
        ? (int)core_id : -LUNE_ERR_NOT_EXIST;
}

static int cpu_get_core_num(cpu_bit_mask_t bit_mask, cpu_core_type_en type)
{
    int core_cnt;
    unsigned int i;

    pthread_spin_lock(&s_cpu_info_lock);
    switch (type) {
    case CPU_CORE_NRT:
        bit_mask = bit_mask & g_cpu_info.nrt_core_occupied;
        break;
    case CPU_CORE_RT_NA:
        bit_mask = bit_mask & g_cpu_info.rt_na_core_occupied;
        break;
    case CPU_CORE_RT_NP:
        bit_mask = bit_mask & g_cpu_info.rt_np_core_occupied;
        break;
    case CPU_CORE_RT_CP:
        bit_mask = bit_mask & g_cpu_info.rt_cp_core_occupied;
        break;
    default:
        pthread_spin_unlock(&s_cpu_info_lock);
        return ERR_SET_ERR(LUNE_ERR_INTERNAL);
    }

    pthread_spin_unlock(&s_cpu_info_lock);

    i = 0, core_cnt = 0;
    while (i < g_cpu_info.num_of_core_avail) {
        if (CPU_IS_BIT_SET(bit_mask, i)) {
            core_cnt++;
        }
        i++;
    }

    return core_cnt;
}

int cpu_get_core_info(cpu_bit_mask_t bit_mask, cpu_core_info_t *info)
{
    if (unlikely(NULL == info)) {
        return ERR_SET_ERR(LUNE_ERR_INTERNAL);
    }

    lune_assert(0 <= (info->nrt_num = cpu_get_core_num(bit_mask, CPU_CORE_NRT)));
    lune_assert(0 <= (info->rt_na_num = cpu_get_core_num(bit_mask, CPU_CORE_RT_NA)));
    lune_assert(0 <= (info->rt_np_num = cpu_get_core_num(bit_mask, CPU_CORE_RT_NP)));
    lune_assert(0 <= (info->rt_cp_num = cpu_get_core_num(bit_mask, CPU_CORE_RT_CP)));

    return 0;
}

/*
    Convert cpu list with comma and dash grammar into actual cpu list.
    See below the examples of cpu list and equivalence:
    cpu list   equivalence
    0-3        0,1,2,3
    0,1-3,5    0,1,2,3,5
*/
int cpu_parse_cpu_list(const char *cpu_list, cpu_bit_mask_t *bmp)
{
#define MOVE_TO_NEXT_TOKEN(p, c)    do { (p) = strchr((p), c); p++; } while (0)
    const char *p;
    unsigned int i, v1, v2;
    char c;
    int ret, num, err;

    *bmp = 0;
    num = 0;
    p = cpu_list;
    while (NULL != p) {
        ret = sscanf(p, "%u%c", &v1, &c);
        if (!cpu_parse_cpu_list_scan_is_valid(ret, c, ",-")) {
            err = -LUNE_ERR_MALFORMED_ARG;
            goto ERR;
        }

        if (!CPU_IS_VALID_CPU_ID(v1)) {
            err = -LUNE_ERR_EXCEED_LIMITS;
            goto ERR;
        }

        if (1 == ret) {
            if (CPU_IS_BIT_SET(*bmp, v1)) {
                err = -LUNE_ERR_INVALID_ARG;
                goto ERR;
            }
            CPU_SET_BIT(*bmp, v1);
            num++;
            goto DONE;
        }

        /* ret = 2 */
        if (',' == c) {
            MOVE_TO_NEXT_TOKEN(p, ',');
            continue;
        }
        
        /* range case */
        MOVE_TO_NEXT_TOKEN(p, '-');
        ret = sscanf(p, "%u%c", &v2, &c);
        if (!cpu_parse_cpu_list_scan_is_valid(ret, c, ",")) {
            err = -LUNE_ERR_MALFORMED_ARG;
            goto ERR;
        }

        if (!CPU_IS_VALID_CPU_ID(v2)) {
            err = -LUNE_ERR_EXCEED_LIMITS;
            goto ERR;
        }

        if (v2 < v1) {
            err = -LUNE_ERR_INVALID_ARG;
            goto ERR;
        }

        for (i = v1; i <= v2; i++) {
            if (CPU_IS_BIT_SET(*bmp, i)) {
                err = -LUNE_ERR_ALREADY_SET;
                goto ERR;
            }
            CPU_SET_BIT(*bmp, i);
            num++;
        }

        if (1 == ret) {
            goto DONE;
        }

        /* ret = 2 & separator case */
        MOVE_TO_NEXT_TOKEN(p, ',');
    }

DONE:
    return num;

ERR:
    *bmp = 0;
    return err;
}

int cpu_init()
{
    if (0 != pthread_spin_init(&s_cpu_info_lock, PTHREAD_PROCESS_PRIVATE)) {
        fprintf(stderr, "failed to initialize cpu lock: %s\n", strerror(errno));
        ERR_SET_ERR(LUNE_ERR_SYS_ERR);
        goto ERR_1;
    }

    g_cpu_info.num_of_core = get_nprocs_conf();
    g_cpu_info.num_of_core_avail = get_nprocs();
    if (unlikely(g_cpu_info.num_of_core_avail > LUNE_MAX_CORE_NUM)) {
        g_cpu_info.num_of_core_avail = LUNE_MAX_CORE_NUM;
    }

    if (g_cpu_info.num_of_core_avail < LUNE_MIN_CORE_NUM) {
        /*
            minimum requirement for cpu cores: 2
            main thread which runs realtime tasks is bound to v1 core exclusively,
            while another thread which runs non-realtime tasks such as packet 
            capture, logging is bound to different core(s) non-exclusively
        */
        fprintf(stderr, "failed to initialize cpu: minimum %d cpu cores required but only %d available\n", 
            LUNE_MIN_CORE_NUM, g_cpu_info.num_of_core_avail);
        ERR_SET_ERR(LUNE_ERR_NO_CPU);
        goto ERR_2;
    }

    g_cpu_info.rt_na_core_occupied = 0;
    g_cpu_info.rt_np_core_occupied = 0;
    g_cpu_info.rt_cp_core_occupied = 0;
    g_cpu_info.nrt_core_occupied = 0;
    g_cpu_info.mask_of_total_core_avail =
        (cpu_bit_mask_t)((LUNE_MAX_CORE_NUM <= g_cpu_info.num_of_core_avail)
        ? (-1) : ((1 << g_cpu_info.num_of_core_avail) - 1));

    return 0;

ERR_2:
    lune_assert(!pthread_spin_destroy(&s_cpu_info_lock));

ERR_1:
    return ERR_GET_LAST_ERR();
}

void cpu_fini()
{
    g_cpu_info.rt_na_core_occupied = 0;
    g_cpu_info.rt_np_core_occupied = 0;
    g_cpu_info.rt_cp_core_occupied = 0;
    g_cpu_info.nrt_core_occupied = 0;

    lune_assert(!pthread_spin_destroy(&s_cpu_info_lock));
}

unsigned int lune_get_curr_core_id()
{
    return s_cpu_curr_core_id;
}
