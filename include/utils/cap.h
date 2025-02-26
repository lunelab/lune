/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2024 Lune Reseau, Inc.
 */

#ifndef __CAP_H__
#define __CAP_H__

#include "kernel/time.h"

const char *cap_get_file_name(void *cap_fp);

void *cap_start(const char *file_name);
void cap_stop(void *cap_fp);
int cap_write_pkt(void *cap_fp, const unsigned char *buf, unsigned int len);
int cap_write_pkt_to_file(void *cap_fp,
    lune_time_val_t *tv, const unsigned char *buf, unsigned int len);
int cap_process_nrt_msg(const unsigned char *msg, unsigned int msg_len);

int cap_init(void);
void cap_fini(void);

#endif