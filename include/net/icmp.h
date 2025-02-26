/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2024 Lune Reseau, Inc.
 */

#ifndef __ICMP_H_PRE__
#define __ICMP_H_PRE__

#include "lune/icmp.h"
#include "lune/list.h"

#include "net/ip.h"

typedef struct _icmp_pcb {
    lune_icmp_socket_callback_t cb;
    ip_t *ipp;
} icmp_pcb_t;

#endif

#ifndef __ICMP_H__
#define __ICMP_H__

#include "net/mac.h"
#include "net/pbuf.h"

#define ICMPV6_GET_SOLICIT_TGT_ADDR(icmph, addr)                    \
    do {                                                            \
        LUNE_IPV6_CPY(addr, (const lune_icmp_hdr_t *)(icmph) + 1);  \
    } while (0)

int icmpv4_input(ip_t *ipv4p, const void *ipv4h, pbuf_t *pbuf);
int icmpv6_input(ip_t *ipv6p, const void *ipv6h, pbuf_t *pbuf);

int icmpv6_send_nb_solicit(ip_t *ipv6p, const lune_ipv6_addr_t *dst_addr);

int icmp_local_init(void);
void icmp_local_fini(void);

extern socket_ops_t g_socket_ops_icmp;

#endif