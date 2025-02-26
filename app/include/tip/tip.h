/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2024 Lune Reseau, Inc.
 * 
 * Lune Test Interface Perf tool
 */

#ifndef __TIP_H__
#define __TIP_H__

int tip_parse_conf_file(const char *tip_conf_file);

void run_tip(void);

#endif