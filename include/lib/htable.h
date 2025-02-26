/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2024 Lune Reseau, Inc.
 */

#ifndef __HTABLE_H__
#define __HTABLE_H__

typedef unsigned int (*htable_hash_func_t)(void *);
typedef int (*htable_compare_func_t)(void *, void *);
typedef void (*htable_free_func_t)(void *);

int htable_local_init(void);
void htable_local_fini(void);

void *htable_create_table(const char *name, 
    htable_hash_func_t hash,
    htable_compare_func_t compare,
    htable_free_func_t free,
    unsigned int offset,
    unsigned int size,
    unsigned int fast_creation);
int htable_delete_table(void *htable);

int htable_insert(void *elem, void *htable, unsigned int skip_search);
void *htable_find(void *elem, void *htable);
int htable_remove(void *elem, void *htable);
int htable_is_added(void *elem, void *htable);

typedef void (*htable_hold_func_t)(void *);
typedef void (*htable_put_func_t)(void *);

void *htable_create_table_mt(const char *name,
    htable_hash_func_t hash,
    htable_compare_func_t compare,
    htable_hold_func_t hold,
    htable_put_func_t put,
    unsigned int offset,
    unsigned int size);
int htable_delete_table_mt(void *htable);

int htable_insert_mt(void *elem, void *htable);
void *htable_find_mt(void *elem, void *htable);
int htable_find_done_mt(void *elem, void *htable);
int htable_remove_mt(void *elem, void *htable);

#endif