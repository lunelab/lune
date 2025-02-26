/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2024 Lune Reseau, Inc.
 */

#ifndef __DRV_INIT_H__
#define __DRV_INIT_H__

int drv_init(void);
void drv_fini(void);

int drv_local_init(void);
void drv_local_fini(void);

#endif