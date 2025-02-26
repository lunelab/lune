/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2024 Lune Reseau, Inc.
 */

#ifndef __LUNE_ID_H__
#define __LUNE_ID_H__

#ifdef __cplusplus
extern "C" {
#endif

typedef enum _lune_id_type {
    LUNE_ID_NET_IF = 0,
    LUNE_ID_MAC,
    LUNE_ID_IPV4,
    LUNE_ID_IPV6,
    LUNE_ID_SOCKET,
    LUNE_ID_MAX,
} lune_id_type_en;

#define LUNE_INVALID_ID     (0xffffffff)

#ifdef __cplusplus
}
#endif

#endif