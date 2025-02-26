/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2024 Lune Reseau, Inc.
 */

#ifndef __LUNE_IDTABLE_H__
#define __LUNE_IDTABLE_H__

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*lune_idtable_free_func_t)(void *);

void *lune_idtable_create_table(const char *name, 
    lune_idtable_free_func_t free,
    unsigned int size);
int lune_idtable_delete_table(void *idt);

int lune_idtable_insert(unsigned int id, void *elem, void *idt);
void *lune_idtable_find(unsigned int id, void *idt);
int lune_idtable_remove(unsigned int id, void *idt);

#ifdef __cplusplus
}
#endif

#endif