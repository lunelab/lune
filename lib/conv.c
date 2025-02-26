/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2024 Lune Reseau, Inc.
 */

#include "lune/conv.h"

#include "lib/conv.h"

unsigned short g_octet_to_str_array[256] = {0};
unsigned char g_str_to_octet_array[65536] = {0};

int conv_init(void)
{
    int i;

    for (i = 0; i < 256; i++) {
        *((char *)&g_octet_to_str_array[i]) = LUNE_HEX_TO_CHAR(i >> 4);
        *((char *)&g_octet_to_str_array[i] + 1) = LUNE_HEX_TO_CHAR(i & 0x0f);
    }

    for (i = 0; i < 65536; i++) {
        if (LUNE_IS_HEX_CHAR(i >> 8)) {
            if (LUNE_IS_HEX_CHAR(i & 0xff)) {
                g_str_to_octet_array[i] =
                    LUNE_CHAR_TO_HEX(i >> 8) + (LUNE_CHAR_TO_HEX(i & 0xff) << 4);
                continue;
            }
        }

        g_str_to_octet_array[i] = 0xff;
    }

    return 0;
}

void conv_fini(void)
{
}
