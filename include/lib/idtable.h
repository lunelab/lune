/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2024 Lune Reseau, Inc.
 */

#include "lib/common.h"

#ifndef __IDTABLE_H__
#define __IDTABLE_H__

#define IDTABLE_PAGE_SIZE_IN_BIT        11
#define IDTABLE_MIN_NUM_OF_PAGE_IN_BIT  2
#define IDTABLE_MAX_NUM_OF_PAGE_IN_BIT  (ID_MAX_NUM_OF_ID_IN_BIT - IDTABLE_PAGE_SIZE_IN_BIT)
#define IDTABLE_MIN_TABLE_SIZE          \
    (1 << (IDTABLE_PAGE_SIZE_IN_BIT + IDTABLE_MIN_NUM_OF_PAGE_IN_BIT))
#define IDTABLE_MAX_TABLE_SIZE          \
    (1 << (IDTABLE_PAGE_SIZE_IN_BIT + IDTABLE_MAX_NUM_OF_PAGE_IN_BIT))

int idtable_local_init(void);
void idtable_local_fini(void);

typedef void (*idtable_free_func_t)(void *);

void *idtable_create_table(const char *name, 
    idtable_free_func_t free,
    unsigned int size);
int idtable_delete_table(void *idt);

int idtable_insert(unsigned int id, void *elem, void *idt);
void *idtable_find(unsigned int id, void *idt);
int idtable_remove(unsigned int id, void *idt);

#endif