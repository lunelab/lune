/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2024 Lune Reseau, Inc.
 */

#ifndef __NET_INIT_H__
#define __NET_INIT_H__

int net_aggr_local_init(void);
void net_aggr_local_fini(void);

int net_proc_local_init(void);
void net_proc_local_fini(void);

int net_init(void);
void net_fini(void);

#endif