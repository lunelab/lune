/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2024 Lune Reseau, Inc.
 */

#ifndef __COMM_H__
#define __COMM_H__

#include "lune/comm.h"

#define COMM_REQ_HANDLER_DECL(type, f)          \
__attribute__((constructor)) static void comm_reg_rt_core_req_##type##_handler(void) {  \
    g_comm_core_req_handler_array[LUNE_COMM_REQ_##type].func = (f);     \
}

typedef struct _comm_core_req_handler {
    lune_comm_req_handle_func_t func;
} comm_core_req_handler_t;

extern comm_core_req_handler_t g_comm_core_req_handler_array[LUNE_COMM_REQ_MAX];

int comm_send_req_to_core(unsigned int id,
    lune_comm_req_type_en type, const void *val, unsigned int len);

int comm_core_send_resp(lune_comm_resp_type_en type,
    const void *val, unsigned int len, int err);
int comm_recv_resp_from_core(unsigned int id,
    lune_comm_resp_type_en *type, int *err, void *pval, unsigned int *plen);

int comm_local_init(void);
void comm_local_fini(void);

#endif