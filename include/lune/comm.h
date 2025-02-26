/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2024 Lune Reseau, Inc.
 */

#ifndef __LUNE_COMM_H__
#define __LUNE_COMM_H__

#include "lune/os/linux.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum _lune_comm_req_type {
    LUNE_COMM_REQ_ADD_NET_IF = 0,
    LUNE_COMM_REQ_DEL_NET_IF,
    LUNE_COMM_REQ_ENABLE_NET_IF,
    LUNE_COMM_REQ_DISABLE_NET_IF,
    LUNE_COMM_REQ_GET_NET_IF_OPT,
    LUNE_COMM_REQ_SET_NET_IF_OPT,
    LUNE_COMM_REQ_GET_CORE_OPT,
    LUNE_COMM_REQ_SET_CORE_OPT,
    LUNE_COMM_REQ_CONNECT_NET_IF,
    LUNE_COMM_REQ_DISCONNECT_NET_IF,
    LUNE_COMM_REQ_APP = 256,
    /* 257~511 reserved for application, messaging APIs are yet to be implemented */
    LUNE_COMM_REQ_MAX = 512,
} lune_comm_req_type_en;

typedef enum _lune_comm_resp_type {
    LUNE_COMM_RESP_ADD_NET_IF = 0,
    LUNE_COMM_RESP_DEL_NET_IF,
    LUNE_COMM_RESP_ENABLE_NET_IF,
    LUNE_COMM_RESP_DISABLE_NET_IF,
    LUNE_COMM_RESP_GET_NET_IF_OPT,
    LUNE_COMM_RESP_SET_NET_IF_OPT,
    LUNE_COMM_RESP_GET_CORE_OPT,
    LUNE_COMM_RESP_SET_CORE_OPT,
    LUNE_COMM_RESP_CONNECT_NET_IF,
    LUNE_COMM_RESP_DISCONNECT_NET_IF,
    LUNE_COMM_RESP_APP = 256,
    /* 257~511 reserved for application, messaging APIs are yet to be implemented */
    LUNE_COMM_RESP_MAX = 512,
} lune_comm_resp_type_en;

typedef void (*lune_comm_req_handle_func_t)(const void *, unsigned int);

int lune_reg_comm_req_handler(lune_comm_req_type_en type, lune_comm_req_handle_func_t func);
int lune_unreg_comm_req_handler(lune_comm_req_type_en type);

#ifdef __cplusplus
}
#endif

#endif