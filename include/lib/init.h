/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2024 Lune Reseau, Inc.
 */

#ifndef __LIB_INIT_H__
#define __LIB_INIT_H__

int lib_local_init(void);
void lib_local_fini(void);

int lib_init(void);
void lib_fini(void);

#endif