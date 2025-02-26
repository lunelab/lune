/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2024 Lune Reseau, Inc.
 * 
 * Lune Test Tcp Perf tool
 */

#ifndef __TTP_H__
#define __TTP_H__

int ttp_parse_conf_file(const char *ttp_conf_file);

void run_ttp(void);

#endif