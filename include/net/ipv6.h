/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2024 Lune Reseau, Inc.
 */

#ifndef __IPV6_H_PRE__
#define __IPV6_H_PRE__

#include "lune/ipv6.h"

typedef struct _ipv6 ipv6_t;
typedef struct _ipv6_pcb {
    lune_ipv6_socket_callback_t cb;
    ip_t *ipv6p;
} ipv6_pcb_t;

#endif

#ifndef __IPV6_H__
#define __IPV6_H__

#include "lune/ip.h"

#include "net/pbuf.h"
#include "net/socket.h"

/* convert unicast address to solicited-node multicast */
#define IPV6_CONV_UC_TO_SN_MC(uc, mc)       \
    do {                                    \
        LUNE_IPV6_CPY((mc), &g_ipv6_solicit_node_multicast_ip); \
        (mc)->addr[3] |= (uc)->addr[3];     \
    } while (0)

typedef struct _ipv6 {
    lune_ipv6_addr_t ip;
    unsigned int pkt_id;
} ipv6_t;

int ipv6_local_init(void);

void ipv6_local_fini(void);

int ipv6_input(lune_id_type_en sub_type, void *sub_entry, pbuf_t *pbuf);

unsigned short ipv6_get_max_hdr_len(ip_t *ipv6p);

int ipv6_output(ip_t *ipv6p,
    const lune_ipv6_addr_t *dst_addr, unsigned char proto, pbuf_t *pbuf);

int ipv6_output_nofrag(ip_t *ipv6p,
    const lune_ipv6_addr_t *dst_addr, unsigned char proto, pbuf_t *pbuf);

extern lune_ipv6_addr_t g_ipv6_solicit_node_multicast_ip;

extern socket_ops_t g_socket_ops_ipv6;

#endif