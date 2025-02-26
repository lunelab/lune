/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2024 Lune Reseau, Inc.
 */

#ifndef __LUNE_TINY_IDTABLE_H__
#define __LUNE_TINY_IDTABLE_H__

#ifdef __cplusplus
extern "C" {
#endif

#define LUNE_TINY_IDTABLE_MAX_SIZE      (64)

typedef void (*lune_tiny_idtable_free_func_t)(void *);
typedef int (*lune_tiny_idtable_iterate_func_t)(unsigned int);

void *lune_tiny_idtable_create_table(const char *name, 
    lune_tiny_idtable_free_func_t free, unsigned int elem_size, unsigned int table_size);
int lune_tiny_idtable_delete_table(void *table);
unsigned int lune_tiny_idtable_new(void *table);
void *lune_tiny_idtable_get(void *table, unsigned int id);
int lune_tiny_idtable_delete(void *table, unsigned int id);
int lune_tiny_idtable_iterate_all(void *table, lune_tiny_idtable_iterate_func_t action);

#ifdef __cplusplus
}
#endif

#endif