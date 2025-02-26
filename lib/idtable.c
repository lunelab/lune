/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2024 Lune Reseau, Inc.
 */

#include "lune/assert.h"
#include "lune/err.h"
#include "lune/id.h"
#include "lune/idtable.h"
#include "lune/list.h"
#include "lune/mem.h"
#include "lune/os/linux.h"

#include "err/err.h"
#include "lib/idtable.h"

#define IDTABLE_IS_VALID_SIZE(s)    (!((s) & ((s) - 1)))
#define IDTABLE_PAGE_SIZE           (1 << IDTABLE_PAGE_SIZE_IN_BIT)
#define IDTABLE_PAGE_MASK           (IDTABLE_PAGE_SIZE - 1)

typedef struct _idtable {
    dlist_node_t node;
    /*
        free() will only be called while deleting entire id table
    */
    idtable_free_func_t free;
    unsigned int size;
    unsigned int num_of_page;
    void **table;
    char name[LUNE_MAX_SHORT_NAME_BUF_LEN];
    struct {
        unsigned int elem_cnt;
    } stats;
} idtable_t;

typedef dlist_head_t idtable_list_t;

static __thread idtable_list_t s_idtable_list;

int idtable_local_init(void)
{
    dlist_init_head(&s_idtable_list);
    return 0;
}

void idtable_local_fini(void)
{
    idtable_t *idt, *idt2;

    dlist_for_each_node_safe(idt, idt2, &s_idtable_list, node) {
        lune_assert(!idtable_delete_table(idt));
    }
}

void *idtable_create_table(const char *name, 
    idtable_free_func_t free,
    unsigned int size)
{
    idtable_t *idt;

    if (NULL == name
        || NULL == free
        || !IDTABLE_IS_VALID_SIZE(size)) {
        ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        return NULL;
    }

    if (strlen(name) > LUNE_MAX_SHORT_NAME_LEN) {
        ERR_SET_ERR(LUNE_ERR_NAME_TOO_LONG);
        return NULL;
    }

    if (size < IDTABLE_MIN_TABLE_SIZE || size > IDTABLE_MAX_TABLE_SIZE) {
        ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        return NULL;
    }

    if (NULL == (idt = lune_malloc(sizeof(idtable_t)))) {
        goto ERR_1;
    }

    dlist_add_tail(&idt->node, &s_idtable_list);
    idt->free = free;
    idt->size = size;
    idt->num_of_page = size >> IDTABLE_PAGE_SIZE_IN_BIT;

    if (NULL == (idt->table = lune_malloc(sizeof(void *) * idt->num_of_page))) {
        goto ERR_2;
    }
    memset(idt->table, 0x00, sizeof(void *) * idt->num_of_page);

    strcpy(idt->name, name);
    idt->stats.elem_cnt = 0;

    return (void *)idt;

ERR_2:
    dlist_del(&idt->node);
    lune_free((void *)idt);

ERR_1:
    return NULL;
}

int idtable_delete_table(void *idt)
{
    idtable_t *t;
    unsigned int i, j, k = 0;
    void **p;

    if (NULL == idt) {
        ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        return LUNE_INVALID_ID;
    }

    t = (idtable_t *)idt;

    for (i = 0; i < t->num_of_page; i++) {
        p = (void **)t->table[i];
        if (NULL != p) {
            for (j = 0; j < IDTABLE_PAGE_SIZE; j++) {
                if (NULL != p[j]) {
                    t->free(p[j]);
                    k++;
                }
            }
            lune_free(p);
        }
    }
    lune_free(t->table);

    lune_assert(t->stats.elem_cnt == k);
    if (t->stats.elem_cnt > 0) {
        lune_log(LUNE_INFO, "%d elements still in id table %s while deleting it", 
            t->stats.elem_cnt, t->name);
    }

    dlist_del(&t->node);
    lune_free((void *)t);

    return 0;
}

int idtable_insert(unsigned int id, void *elem, void *idt)
{
    idtable_t *t = (idtable_t *)idt;
    unsigned int idx, idx2;
    void **p;

    if (NULL == elem || NULL == t || id >= t->size) {
        return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
    }

    idx = id >> IDTABLE_PAGE_SIZE_IN_BIT;
    if (NULL != (p = t->table[idx])) {
        idx2 = id & IDTABLE_PAGE_MASK;
        if (NULL != p[idx2]) {
            return ERR_SET_ERR(LUNE_ERR_ALREADY_EXIST);
        }
        p[idx2] = elem;
        t->stats.elem_cnt++;
        return 0;
    }

    if (NULL == (p = lune_malloc(sizeof(void *) * IDTABLE_PAGE_SIZE))) {
        return ERR_GET_LAST_ERR();
    }
    memset(p, 0x00, sizeof(void *) * IDTABLE_PAGE_SIZE);

    idx2 = id & IDTABLE_PAGE_MASK;
    p[idx2] = elem;
    t->stats.elem_cnt++;
    t->table[idx] = p;

    return 0;
}

void *idtable_find(unsigned int id, void *idt)
{
    idtable_t *t = (idtable_t *)idt;
    unsigned int idx, idx2;
    void **p;

    if (NULL == t || id >= t->size) {
        ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        return NULL;
    }

    idx = id >> IDTABLE_PAGE_SIZE_IN_BIT;
    if (NULL == (p = t->table[idx])) {
        return NULL;
    }

    idx2 = id & IDTABLE_PAGE_MASK;
    return p[idx2];
}

int idtable_remove(unsigned int id, void *idt)
{
    idtable_t *t = (idtable_t *)idt;    
    unsigned int idx, idx2;
    void **p;

    if (NULL == t || id >= t->size) {
        return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
    }

    idx = id >> IDTABLE_PAGE_SIZE_IN_BIT;
    if (NULL == (p = t->table[idx])) {
        return ERR_SET_ERR(LUNE_ERR_ID_NOT_FOUND);
    }

    idx2 = id & IDTABLE_PAGE_MASK;
    if (NULL == p[idx2]) {
        return ERR_SET_ERR(LUNE_ERR_ID_NOT_FOUND);
    }

    p[idx2] = NULL;
    t->stats.elem_cnt--;
    return 0;
}

/* a set of wrapper functions for id table */
void *lune_idtable_create_table(const char *name, 
    lune_idtable_free_func_t free,
    unsigned int size)
{
    return idtable_create_table(name, free, size);
}

int lune_idtable_delete_table(void *idt)
{
    return idtable_delete_table(idt);
}

int lune_idtable_insert(unsigned int id, void *elem, void *idt)
{
    return idtable_insert(id, elem, idt);
}

void *lune_idtable_find(unsigned int id, void *idt)
{
    return idtable_find(id, idt);
}

int lune_idtable_remove(unsigned int id, void *idt)
{
    return idtable_remove(id, idt);
}
