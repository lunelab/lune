/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2024 Lune Reseau, Inc.
 */

#ifndef __CPU_H__
#define __CPU_H__

#define CPU_CLEAR_BIT(bm, n)        \
    do { (bm) &= ~((unsigned long long)1 << (n)); } while (0)
#define CPU_SET_BIT(bm, n)          \
    do { (bm) |= ((unsigned long long)1 << (n)); } while (0)
#define CPU_IS_BIT_SET(bm, n)       ((bm) & ((unsigned long long)1 << (n)))

typedef enum _cpu_core_type {
    CPU_CORE_NRT = 0,
    CPU_CORE_RT_NA,
    CPU_CORE_RT_NP,
    CPU_CORE_RT_CP,
    CPU_CORE_IDLE,
} cpu_core_type_en;

typedef struct _cpu_core_info {
    unsigned int nrt_num;
    unsigned int rt_na_num;
    unsigned int rt_np_num;
    unsigned int rt_cp_num;
} cpu_core_info_t;

typedef unsigned long long cpu_bit_mask_t;

#define CPU_IS_VALID_CPU_ID(id)     ((id) < g_cpu_info.num_of_core_avail)

typedef struct _cpu_info {
    unsigned int num_of_core;
    unsigned int num_of_core_avail;
    /* support maximum 64 cores (64-bit) */
    cpu_bit_mask_t rt_na_core_occupied;
    cpu_bit_mask_t rt_np_core_occupied;
    cpu_bit_mask_t rt_cp_core_occupied;
    cpu_bit_mask_t nrt_core_occupied;
    cpu_bit_mask_t mask_of_total_core_avail;
} cpu_info_t;

extern cpu_info_t g_cpu_info;

/*
    Convert cpu list with comma and range grammar into actual cpu list.
    See below the examples of cpu list and equivalence:
    cpu list   equivalence
    0-3        0,1,2,3
    0,1-3,5    0,1,2,3,5
*/
int cpu_parse_cpu_list(const char *cpu_list, cpu_bit_mask_t *bmp);

int cpu_init(void);
void cpu_fini(void);

unsigned int cpu_get_num_of_core_avail(void);
int cpu_get_first_core(cpu_bit_mask_t bit_mask, cpu_core_type_en type);
int cpu_get_core_info(cpu_bit_mask_t bit_mask, cpu_core_info_t *info);
int cpu_get_core_bit_mask(cpu_bit_mask_t *bit_mask, cpu_core_type_en type);

int cpu_set_affinity(unsigned int core_id, cpu_core_type_en type);
int cpu_clear_affinity(unsigned int core_id);

#endif