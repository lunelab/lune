/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2024 Lune Reseau, Inc.
 */

#ifndef __IDLIST_H__
#define __IDLIST_H__

int idlist_local_init(void);
void idlist_local_fini(void);

void *idlist_create_list(const char *name);
int idlist_delete_list(void *idl);

unsigned int idlist_get_new_id(void *idl);
int idlist_del_id(unsigned int id, void *idl);

#endif