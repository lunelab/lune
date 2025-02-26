/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2024 Lune Reseau, Inc.
 */

#ifndef __LUNE_COMMON_H__
#define __LUNE_COMMON_H__

#include "lune/err.h"
#include "lune/os/linux.h"

#ifdef __cplusplus
extern "C" {
#endif

#define ALIGN_8B(x)                 (((x) + (7)) & ~(7))
#define IS_POW2_NUM(n)              (!((n) & ((n) - 1)))

#define LUNE_MAX_SHORT_NAME_LEN     (63)
#define LUNE_MAX_SHORT_NAME_BUF_LEN (LUNE_MAX_SHORT_NAME_LEN + 1)
#define LUNE_MAX_NAME_LEN           (LUNE_MAX_SHORT_NAME_BUF_LEN * 2 - 1)
#define LUNE_MAX_NAME_BUF_LEN       (LUNE_MAX_NAME_LEN + 1)
#define LUNE_MAX_LONG_NAME_LEN      (LUNE_MAX_NAME_BUF_LEN * 2 - 1)
#define LUNE_MAX_LONG_NAME_BUF_LEN  (LUNE_MAX_LONG_NAME_LEN + 1)

#define LUNE_MIN(a, b)          \
    __extension__({             \
        typeof(a) _a = (a);     \
        typeof(b) _b = (b);     \
        _a < _b ? _a : _b;      \
    })

#define LUNE_MAX(a, b)          \
    __extension__({             \
        typeof(a) _a = (a);     \
        typeof(b) _b = (b);     \
        _a > _b ? _a : _b;      \
    })

static inline int lune_rand(unsigned int min, unsigned int max)
{
    if (unlikely(min >= max)) {
        return lune_set_err_no(LUNE_ERR_INVALID_ARG);
    }

    return (int)((lrand48() % ((unsigned long long)max - (unsigned long long)min + 1)) + min);
}

static inline int lune_get_num_of_digits(int num)
{
    if (unlikely(0 == num)) {
        return lune_set_err_no(LUNE_ERR_INVALID_ARG);
    }

    return floor(log10(abs(num))) + 1;
}

/*
    replace all occurence of c1 in s with c2
*/
static inline void lune_str_replace_char(char *s, char c1, char c2)
{
    int i = 0;

    while (s[i] != 0) {
        if (s[i] == c1) {
            s[i] = c2;
        }
        i++;
    }
}

#ifdef __cplusplus
}
#endif

#endif