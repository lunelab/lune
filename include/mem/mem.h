/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2024 Lune Reseau, Inc.
 */

#ifndef __MEM_H__
#define __MEM_H__

#include "lune/common.h"
#include "lune/err.h"
#include "lune/list.h"
#include "lune/mem.h"
#include "lune/os/linux.h"

#include "err/err.h"

typedef struct _mem_d_array {
    char name[LUNE_MAX_SHORT_NAME_BUF_LEN];
    dlist_node_t node;
    void **array;
    unsigned int array_size;
    unsigned int elem_size;
    unsigned int last;
} mem_d_array_t;

void *mem_create_d_array(const char *name,
    unsigned int elem_size, unsigned int array_size);
void mem_delete_d_array(void *array);
void *mem_d_array_alloc(void *array);

static inline void *mem_d_array_get(void *array, unsigned int idx)
{
    mem_d_array_t *ma = (mem_d_array_t *)array;

    if (NULL == ma || idx >= ma->array_size) {
        (void)ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        return NULL;
    }

    return ma->array[idx];
}

typedef struct _mem_s_array {
    char name[LUNE_MAX_SHORT_NAME_BUF_LEN];
    dlist_node_t node;
    dlist_head_t free_list_head;
    void *array;
    unsigned int array_size;
    unsigned int elem_size;
} mem_s_array_t;

typedef struct _mem_s_array_elem_hdr {
    dlist_node_t node;
} mem_s_array_elem_hdr_t;

#define MEM_STATIC_ARRAY_LIST_GET_IDX(s_array, elem)                                        \
    ((((unsigned char *)(elem)) - sizeof(mem_s_array_elem_hdr_t))                           \
    - (unsigned char *)(((mem_s_array_t *)(s_array))->array)) /                             \
    (((mem_s_array_t *)(s_array))->elem_size + sizeof(mem_s_array_elem_hdr_t))

#define MEM_STATIC_ARRAY_LIST_GET_MEM(s_array, idx)                                         \
    ((void *)((unsigned char *)(((mem_s_array_t *)(s_array))->array)                        \
    + (((mem_s_array_t *)(s_array))->elem_size + sizeof(mem_s_array_elem_hdr_t)) * (idx)    \
    + sizeof(mem_s_array_elem_hdr_t)))

typedef void (*mem_s_array_init_func_t)(void *);
typedef void (*mem_s_array_free_func_t)(void *);

void *mem_create_s_array(const char *name,
    unsigned int elem_size, unsigned int array_size, mem_s_array_init_func_t func);
void mem_delete_s_array(void *array, mem_s_array_free_func_t func);
void *mem_s_array_alloc(void *array);
void mem_s_array_free(void *array, void *elem);

#ifdef LUNE_DEBUG
int mem_start_local_mem_stats_report(void);
void mem_stop_local_mem_stats_report(void);
#endif

int mem_local_init(void);
void mem_local_fini(void);

int mem_init(void);
void mem_fini(void);

#endif