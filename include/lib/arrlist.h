/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2024 Lune Reseau, Inc.
 */

#ifndef __ARRLIST_H__
#define __ARRLIST_H__

#include "lune/common.h"
#include "lune/list.h"

#define ARRLIST_IS_EMPTY(al)                        \
    (0 == ((arrlist_t *)(al))->inuse_node_cnt)

#define ARRLIST_GET_ELEM_IDX(e)                     \
    (((arrlist_node_t *)(((unsigned char *)e) - sizeof(arrlist_node_t)))->idx)
#define ARRLIST_GET_ELEM_BY_NODE(n)                 \
    ((void *)(((unsigned char *)n) + sizeof(arrlist_node_t)))
#define ARRLIST_GET_ELEM_BY_IDX(al, idx)            \
    (void *)(((unsigned char *)(al))                \
        + sizeof(arrlist_t)                         \
        + ((arrlist_t *)(al))->node_size * (idx)    \
        + sizeof(arrlist_node_t))
#define ARRLIST_ELEM_EXIST(e)                       \
    ARRLIST_IS_NODE_INUSE(ARRLIST_GET_NODE_BY_ELEM(e))

#define ARRLIST_GET_NODE_IDX(n)                     (((arrlist_node_t *)n)->idx)
#define ARRLIST_GET_NODE_BY_ELEM(e)                 \
    ((arrlist_node_t *)(((unsigned char *)e) - sizeof(arrlist_node_t)))

#define ARRLIST_FOR_EACH_NODE(al, n)                \
    dlist_for_each_node_2(n, &((arrlist_t *)(al))->inuse_list, arrlist_node_t, node)

#define ARRLIST_FOR_EACH_NODE_SAFE(al, n, n2)       \
    dlist_for_each_node_safe_2(n, n2,               \
        &((arrlist_t *)(al))->inuse_list, arrlist_node_t, node)

typedef struct _arrlist_node arrlist_node_t;

typedef struct _arrlist {
    dlist_head_t free_list;
    dlist_head_t inuse_list;
    unsigned int inuse_node_cnt;
    unsigned int node_size;
    arrlist_node_t *curr_node;      /* round-robin */
    char name[LUNE_MAX_SHORT_NAME_BUF_LEN];
} arrlist_t;

typedef struct _arrlist_node {
    dlist_node_t node;
    unsigned int idx;
#define ARRLIST_FLAG_NODE_INUSE                     0x00000001
#define ARRLIST_IS_NODE_INUSE(n)                    \
    (((arrlist_node_t *)n)->flags & ARRLIST_FLAG_NODE_INUSE)
#define ARRLIST_SET_NODE_INUSE(n)                   \
    do { ((arrlist_node_t *)n)->flags =             \
        (((arrlist_node_t *)n)->flags | (ARRLIST_FLAG_NODE_INUSE)); } while (0)
#define ARRLIST_SET_NODE_FREE(n)                    \
    do { ((arrlist_node_t *)n)->flags =             \
        (((arrlist_node_t *)n)->flags & (~ARRLIST_FLAG_NODE_INUSE)); } while (0)
    unsigned int flags;
} arrlist_node_t;

int arrlist_init(void);
void arrlist_fini(void);

void *arrlist_create_s_list(const char *name,
    unsigned int array_size,
    unsigned int elem_size);
int arrlist_delete_s_list(void *al);

void *arrlist_s_list_alloc_elem(void *al);
void arrlist_s_list_free_elem(void *al, void *e);
/*
    move and get next element available in static array list
*/
void *arrlist_s_list_get_next_elem(void *al);

#endif