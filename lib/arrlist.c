/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2024 Lune Reseau, Inc.
 */

#include "lune/assert.h"
#include "lune/common.h"
#include "lune/err.h"
#include "lune/id.h"
#include "lune/log.h"
#include "lune/mem.h"
#include "lune/os/linux.h"

#include "err/err.h"
#include "lib/common.h"
#include "lib/arrlist.h"
#include "log/log.h"

int arrlist_init(void)
{
    return 0;
}

void arrlist_fini(void)
{
}

void *arrlist_create_s_list(const char *name,
    unsigned int array_size,
    unsigned int elem_size)
{
    arrlist_t *al;
    arrlist_node_t *n;
    unsigned int i;

    if (NULL == name
        || 0 == array_size
        || 0 == elem_size) {
        ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        goto ERR_1;
    }

    if (strlen(name) > LUNE_MAX_SHORT_NAME_LEN) {
        ERR_SET_ERR(LUNE_ERR_NAME_TOO_LONG);
        goto ERR_1;
    }

    if (NULL == (al = lune_malloc(sizeof(arrlist_t)
        + array_size * (sizeof(arrlist_node_t) + ALIGN_8B(elem_size))))) {
        goto ERR_1;
    }

    dlist_init_head(&al->free_list);
    dlist_init_head(&al->inuse_list);
    al->inuse_node_cnt = 0;
    al->node_size = sizeof(arrlist_node_t) + ALIGN_8B(elem_size);
    al->curr_node = NULL;
    strcpy(al->name, name);
    for (i = 0, n = (arrlist_node_t *)((unsigned char *)al + sizeof(arrlist_t));
        i < array_size;
        i++, n = (arrlist_node_t *)((unsigned char *)n + al->node_size)) {
        dlist_add_tail(&n->node, &al->free_list);
        n->idx = i;
        n->flags = 0;
    }

    return (void *)al;

ERR_1:
    return NULL;
}

int arrlist_delete_s_list(void *al)
{
    arrlist_t *l;

    if (NULL == al) {
        return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
    }

    l = (arrlist_t *)al;
    if (!dlist_is_empty(&l->inuse_list)) {
        lune_log(LUNE_INFO, "%d element(s) still in array list %s while deleting it",
            l->inuse_node_cnt, l->name);
    }

    lune_free((void *)l);

    return 0;
}

void *arrlist_s_list_alloc_elem(void *al)
{
    arrlist_t *l;
    arrlist_node_t *n;

    if (unlikely(NULL == al)) {
        ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        return NULL;
    }

    l = (arrlist_t *)al;
    if (dlist_is_empty(&l->free_list)) {
        ERR_SET_ERR(LUNE_ERR_EXCEED_LIMITS);
        return NULL;
    }

    n = dlist_first(&l->free_list, arrlist_node_t, node);
#ifdef LUNE_DEBUG
    lune_assert(!ARRLIST_IS_NODE_INUSE(n));
#endif
    dlist_del(&n->node);
    dlist_add_tail(&n->node, &l->inuse_list);
    ARRLIST_SET_NODE_INUSE(n);
    if (0 == l->inuse_node_cnt++) {
        /* first node to be allocated */
        l->curr_node = n;
    }

    return ARRLIST_GET_ELEM_BY_NODE(n);
}

void arrlist_s_list_free_elem(void *al, void *e)
{
    arrlist_t *l = (arrlist_t *)al;
    arrlist_node_t *n;

    if (unlikely(NULL == l || NULL == e)) {
        lune_log(LUNE_WARN, "failed to free element in static array list: %s",
            ERR_GET_ERR_STR(ERR_SET_ERR(LUNE_ERR_INVALID_ARG)));
        return;
    }

    n = ARRLIST_GET_NODE_BY_ELEM(e);
#ifdef LUNE_DEBUG
    lune_assert(ARRLIST_IS_NODE_INUSE(n));
#endif
    if (0 == --l->inuse_node_cnt) {
#ifdef LUNE_DEBUG
        lune_assert(l->curr_node == n);
#endif
        l->curr_node = NULL;
    } else if (l->curr_node == n) {
        l->curr_node = dlist_next_node((arrlist_node_t *)l->curr_node,
            &l->inuse_list, node, 1);
    }
    dlist_del(&n->node);
    dlist_add_tail(&n->node, &l->free_list);
    ARRLIST_SET_NODE_FREE(n);
}

void *arrlist_s_list_get_next_elem(void *al)
{
    arrlist_t *l;
    void *e;

    if (unlikely(NULL == al)) {
        ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        return NULL;
    }

    l = (arrlist_t *)al;
    if (NULL == l->curr_node) {
        ERR_SET_ERR(LUNE_ERR_EMPTY);
        return NULL;
    }

    e = ARRLIST_GET_ELEM_BY_NODE(l->curr_node);
#ifdef LUNE_DEBUG
    lune_assert(l->inuse_node_cnt > 0);
    lune_assert(!dlist_is_empty(&l->inuse_list));
    lune_assert(ARRLIST_ELEM_EXIST(e));
#endif
    l->curr_node = dlist_next_node(l->curr_node, &l->inuse_list, node, 1);
    return e;
}
