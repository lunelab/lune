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
#include "lune/tiny_idtable.h"

#include "err/err.h"

/* tiny id table */

typedef struct _tiny_idtable {
    unsigned long long inuse_bits;
    unsigned int elem_size;
    unsigned short table_size;
    unsigned short offset;
    lune_tiny_idtable_free_func_t free;
    char name[LUNE_MAX_SHORT_NAME_BUF_LEN];
} tiny_idtable_t;

void *lune_tiny_idtable_create_table(const char *name, 
    lune_tiny_idtable_free_func_t free, unsigned int elem_size, unsigned int table_size)
{
    tiny_idtable_t *tidt;

    if (NULL == name || 0 == elem_size || table_size > LUNE_TINY_IDTABLE_MAX_SIZE) {
        ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        return NULL;
    }

    if (strlen(name) > LUNE_MAX_SHORT_NAME_LEN) {
        ERR_SET_ERR(LUNE_ERR_NAME_TOO_LONG);
        return NULL;
    }

    elem_size = ALIGN_8B(elem_size);
    if (NULL == (tidt = lune_malloc(sizeof(tiny_idtable_t) + elem_size * table_size))) {
        return NULL;
    }

    tidt->inuse_bits = 0;
    tidt->elem_size = elem_size;
    tidt->table_size = table_size;
    tidt->offset = 0;
    tidt->free = free;
    strcpy(tidt->name, name);

    return (void *)tidt;
}

int lune_tiny_idtable_delete_table(void *table)
{
    tiny_idtable_t *tidt = (tiny_idtable_t *)table;
    int i;

    if (NULL == tidt) {
        return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
    }

    if (NULL != tidt->free) {
        for (i = 0; i < tidt->table_size; i++) {
            if (tidt->inuse_bits & ((unsigned long long)1 << i)) {
                tidt->free((void *)((unsigned char *)tidt + sizeof(tiny_idtable_t) + tidt->elem_size * i));
            }
        }
    }

    lune_free(tidt);
    return 0;
}

unsigned int lune_tiny_idtable_new(void *table)
{
    tiny_idtable_t *tidt = (tiny_idtable_t *)table;
    int i, offset;

    if (NULL == tidt) {
        ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        return LUNE_INVALID_ID;
    }

    i = 0;
    while (i < tidt->table_size) {
        if (!(tidt->inuse_bits & ((unsigned long long)1 << tidt->offset))) {
            tidt->inuse_bits |= ((unsigned long long)1 << tidt->offset);
            offset = tidt->offset;
            tidt->offset = (tidt->offset + 1) % tidt->table_size;
            return offset;
        }
        i++;
    }

    ERR_SET_ERR(LUNE_ERR_EXCEED_LIMITS);
    return LUNE_INVALID_ID;
}

void *lune_tiny_idtable_get(void *table, unsigned int id)
{
    tiny_idtable_t *tidt = (tiny_idtable_t *)table;

    if (NULL == tidt || id >= tidt->table_size) {
        ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        return NULL;
    }

    if (!(tidt->inuse_bits & ((unsigned long long)1 << id))) {
        ERR_SET_ERR(LUNE_ERR_ID_NOT_FOUND);
        return NULL;
    }

    return (void *)((unsigned char *)tidt + sizeof(tiny_idtable_t) + tidt->elem_size * id);
}

int lune_tiny_idtable_delete(void *table, unsigned int id)
{
    tiny_idtable_t *tidt = (tiny_idtable_t *)table;

    if (NULL == tidt || id >= tidt->table_size) {
        return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
    }

    if (!(tidt->inuse_bits & ((unsigned long long)1 << id))) {
        return ERR_SET_ERR(LUNE_ERR_NOT_EXIST);
    }

    tidt->inuse_bits &= (~((unsigned long long)1 << id));
    return 0;
}

int lune_tiny_idtable_iterate_all(void *table, lune_tiny_idtable_iterate_func_t action)
{
    tiny_idtable_t *tidt = (tiny_idtable_t *)table;
    int i, failed_cnt;

    if (NULL == tidt || NULL == action) {
        return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
    }

    failed_cnt = 0;
    for (i = 0; i < tidt->table_size; i++) {
        if (tidt->inuse_bits & ((unsigned long long)1 << i)) {
            if (0 != action(i)) {
                failed_cnt++;
            }
        }
    }

    if (failed_cnt > 0) {
        lune_log(LUNE_INFO, "%d failed while iterating tiny id table %s", failed_cnt, tidt->name);
    }

    return 0;
}
