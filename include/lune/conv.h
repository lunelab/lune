/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2024 Lune Reseau, Inc.
 */

#ifndef __LUNE_CONV_H__
#define __LUNE_CONV_H__

#ifdef __cplusplus
extern "C" {
#endif

#define LUNE_IS_DEC_CHAR(c)     (((c) >= '0' && (c) <= '9'))

#define LUNE_IS_HEX_CHAR(c)     \
    (((c) >= '0' && (c) <= '9') || ((c) >= 'A' && (c) <= 'F') || ((c) >= 'a' && (c) <= 'f'))

#define LUNE_HEX_TO_CHAR(c)  \
    (((c) <= 9) ? ((c) + '0') : ((c) + 'A' - 10))
#define LUNE_CHAR_TO_HEX(c)  \
    (((c) >= '0' && (c) <= '9') ? ((c) - '0') : (((c) >= 'A' && (c) <= 'F') ? ((c) - 'A' + 10) : ((c) - 'a' + 10)))

#define LUNE_CONV_OCTET_TO_STR(in, out)     \
    do { *(unsigned short *)(out) = g_octet_to_str_array[*((const unsigned char *)(in))]; } while (0)
#define LUNE_CONV_STR_TO_OCTET(in, out)     \
    do { *(unsigned char *)(out) = g_str_to_octet_array[*((const unsigned short *)(in))]; } while (0)

extern unsigned short g_octet_to_str_array[];
extern unsigned char g_str_to_octet_array[];

#ifdef __cplusplus
}
#endif

#endif