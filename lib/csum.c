/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2024 Lune Reseau, Inc.
 */

#include "lune/csum.h"
#include "lune/ipv4.h"
#include "lune/net.h"

#include "lib/csum.h"

static inline unsigned add32_with_carry(unsigned a, unsigned b)
{
    asm("addl %2,%0\n\t"
        "adcl $0,%0" 
        : "=r" (a) 
        : "0" (a), "r" (b));
    return a;
}

static inline unsigned short from32to16(unsigned a) 
{
    unsigned short b = a >> 16; 
    asm("addw %w2,%w0\n\t"
        "adcw $0,%w0\n" 
        : "=r" (b)
        : "0" (b), "r" (a));
    return b;
}

static inline unsigned int do_csum(const unsigned char *buf, unsigned int len)
{
    unsigned odd, cnt;
    unsigned long result = 0;

    if (0 == len) {
        return result;
    }

    odd = 1 & (const unsigned long)buf;
    if (odd) {
        result = *buf << 8;
        len--;
        buf++;
    }

    cnt = len >> 1; /* nr of 16-bit words */
    if (cnt) {
        if (2 & (unsigned long)buf) {
            result += *(const unsigned short *)buf;
            cnt--;
            len -= 2;
            buf += 2;
        }

        cnt >>= 1;  /* nr of 32-bit words */
        if (cnt) {
            unsigned long zero;
            unsigned cnt64;
            if (4 & (const unsigned long)buf) {
                result += *(const unsigned int *)buf;
                cnt--;
                len -= 4;
                buf += 4;
            }

            cnt >>= 1;  /* nr of 64-bit words */

            /* main loop using 64byte blocks */
            zero = 0;
            cnt64 = cnt >> 3;

            while (cnt64) {
                asm("addq 0*8(%[src]),%[res]\n\t"
                    "adcq 1*8(%[src]),%[res]\n\t"
                    "adcq 2*8(%[src]),%[res]\n\t"
                    "adcq 3*8(%[src]),%[res]\n\t"
                    "adcq 4*8(%[src]),%[res]\n\t"
                    "adcq 5*8(%[src]),%[res]\n\t"
                    "adcq 6*8(%[src]),%[res]\n\t"
                    "adcq 7*8(%[src]),%[res]\n\t"
                    "adcq %[zero],%[res]"
                    : [res] "=r" (result)
                    : [src] "r" (buf), [zero] "r" (zero),
                    "[res]" (result));
                buf += 64;
                cnt64--;
            }

            /* last upto 7 8byte blocks */
            cnt %= 8; 
            while (cnt) { 
                asm("addq %1,%0\n\t"
                    "adcq %2,%0\n" 
                        : "=r" (result)
                    : "m" (*(const unsigned long *)buf), 
                    "r" (zero),  "0" (result));
                --cnt; 
                buf += 8;
            }

            result = add32_with_carry(result >> 32, result & 0xffffffff); 
            if (len & 4) {
                result += *(const unsigned int *)buf;
                buf += 4;
            }
        }

        if (len & 2) {
            result += *(const unsigned short *)buf;
            buf += 2;
        }
    }

    if (len & 1) {
        result += *buf;
    }

    result = add32_with_carry(result>>32, result & 0xffffffff); 

    if (odd) { 
        result = from32to16(result);
        result = ((result >> 8) & 0xff) | ((result & 0xff) << 8);
    }

    return result;
}

unsigned int csum_partial(const unsigned char *buf, int len, unsigned int sum)
{
    return add32_with_carry(do_csum(buf, len), sum); 
}

unsigned short csum_fold(unsigned int sum)
{
    asm(
        "addl %1, %0        ;\n"
        "adcl $0xffff, %0    ;\n"
        : "=r" (sum)
        : "r" (sum << 16), "0" (sum & 0xffff0000)
        );

    return (~sum) >> 16;
}

unsigned short lune_calc_ipv4_csum(void *hdr, unsigned short hdr_len)
{
    return csum_fold(csum_partial((unsigned char *)hdr, hdr_len, 0));
}

/*
    for some (mysterious) reason the following function doesn't work (checksum
    incorrect) when compiler optimization is turned on. similar functions work
    perfectly in tcp/udp stack.

    turn it off for now as a workaround and will address the issue afterwards
*/
#pragma GCC push_options
#pragma GCC optimize ("O0")

unsigned short lune_calc_l4_csum(void *hdr,
    lune_ipv4_addr_t src_addr, 
    lune_ipv4_addr_t dst_addr, 
    unsigned short l4_len,
    unsigned char proto)
{
    lune_ipv4_psd_hdr_t ipv4h;
    unsigned int sum;

    sum = csum_partial((unsigned char *)hdr, l4_len, 0);

    ipv4h.src_addr = lune_htonl(src_addr);
    ipv4h.dst_addr = lune_htonl(dst_addr);
    ipv4h.z = 0;
    ipv4h.proto = proto;
    ipv4h.len = lune_htons(l4_len);

    sum = csum_partial((unsigned char *)&ipv4h, sizeof(lune_ipv4_psd_hdr_t), sum);
    return csum_fold(sum);
}

#pragma GCC pop_options
