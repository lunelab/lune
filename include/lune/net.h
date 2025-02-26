/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2024 Lune Reseau, Inc.
 */

#ifndef __NET_H__
#define __NET_H__

#ifdef __cplusplus
extern "C" {
#endif

static inline unsigned short lune_htons(unsigned short n)
{
#ifdef LUNE_BIG_ENDIAN
    return n;
#else
    return ((n & 0xff) << 8) | ((n & 0xff00) >> 8);
#endif
}

static inline unsigned short lune_ntohs(unsigned short n)
{
#ifdef LUNE_BIG_ENDIAN
    return n;
#else
    return ((n & 0xff) << 8) | ((n & 0xff00) >> 8);
#endif
}

static inline unsigned int lune_htonl(unsigned int n)
{
#ifdef LUNE_BIG_ENDIAN
    return n;
#else
    return ((n & 0xff) << 24) 
        |((n & 0xff00) << 8) 
        |((n & 0xff0000) >> 8) 
        |((n & 0xff000000) >> 24);
#endif
}

static inline unsigned int lune_ntohl(unsigned int n)
{
#ifdef LUNE_BIG_ENDIAN
    return n;
#else
    return ((n & 0xff) << 24) 
        |((n & 0xff00) << 8) 
        |((n & 0xff0000) >> 8) 
        |((n & 0xff000000) >> 24);
#endif
}

static inline unsigned long long lune_htonll(unsigned long long n)
{
#ifdef LUNE_BIG_ENDIAN
    return n;
#else
    return ((((n) & (unsigned long long)(0x00000000000000ff)) << 56) 
        | (((n) & (unsigned long long)(0x000000000000ff00)) << 40) 
        | (((n) & (unsigned long long)(0x0000000000ff0000)) << 24) 
        | (((n) & (unsigned long long)(0x00000000ff000000)) << 8) 
        | (((n) & (unsigned long long)(0x000000ff00000000)) >> 8) 
        | (((n) & (unsigned long long)(0x0000ff0000000000)) >> 24) 
        | (((n) & (unsigned long long)(0x00ff000000000000)) >> 40)
        | (((n) & (unsigned long long)(0xff00000000000000)) >> 56));
#endif
}

static inline unsigned long long lune_ntohll(unsigned long long n)
{
#ifdef LUNE_BIG_ENDIAN
    return n;
#else
    return ((((n) & (unsigned long long)(0x00000000000000ff)) << 56) 
        | (((n) & (unsigned long long)(0x000000000000ff00)) << 40) 
        | (((n) & (unsigned long long)(0x0000000000ff0000)) << 24) 
        | (((n) & (unsigned long long)(0x00000000ff000000)) << 8) 
        | (((n) & (unsigned long long)(0x000000ff00000000)) >> 8) 
        | (((n) & (unsigned long long)(0x0000ff0000000000)) >> 24) 
        | (((n) & (unsigned long long)(0x00ff000000000000)) >> 40)
        | (((n) & (unsigned long long)(0xff00000000000000)) >> 56));
#endif
}

static inline unsigned short lune_swaps(unsigned short n)
{
    return ((n & 0xff) << 8) | ((n & 0xff00) >> 8);
}

static inline unsigned long long lune_swapll(unsigned long long n)
{
    return ((((n) & (unsigned long long)(0x00000000000000ff)) << 56) 
        | (((n) & (unsigned long long)(0x000000000000ff00)) << 40) 
        | (((n) & (unsigned long long)(0x0000000000ff0000)) << 24) 
        | (((n) & (unsigned long long)(0x00000000ff000000)) << 8) 
        | (((n) & (unsigned long long)(0x000000ff00000000)) >> 8) 
        | (((n) & (unsigned long long)(0x0000ff0000000000)) >> 24) 
        | (((n) & (unsigned long long)(0x00ff000000000000)) >> 40)
        | (((n) & (unsigned long long)(0xff00000000000000)) >> 56));
}

#ifdef __cplusplus
}
#endif

#endif