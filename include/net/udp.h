/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2024 Lune Reseau, Inc.
 */

#ifndef __UDP_H_PRE__
#define __UDP_H_PRE__

#include "lune/list.h"
#include "lune/udp.h"

typedef struct _udp_pcb {
    lune_udp_socket_callback_t cb;
    ip_t *ipp;
    unsigned short port;
#define UDP_MULTICAST_FLAG              0x0001
#define UDP_IS_MULTICAST(pcb)           ((pcb)->flags & UDP_MULTICAST_FLAG)
#define UDP_SET_MULTICAST(pcb)          \
    do { (pcb)->flags = ((pcb)->flags | (UDP_MULTICAST_FLAG)); } while (0)
#define UDP_CLEAR_MULTICAST(pcb)        \
    do { (pcb)->flags = ((pcb)->flags & (~UDP_MULTICAST_FLAG)); } while (0)
    unsigned short flags;
    /* the following fields are only used for multicast */
    lune_ipv4_addr_t group_addr;
    dlist_node_t node;      
} udp_pcb_t;

#endif

#ifndef __UDP_H__
#define __UDP_H__

#include "net/igmp.h"
#include "net/mac.h"
#include "net/pbuf.h"

int udp_local_init(void);
void udp_local_fini(void);

int udp_input_multicast(igmp_group_t *igp, lune_ipv4_hdr_t *ipv4h, pbuf_t *pbuf);
int udp_input_unicast(ip_t *ipp, const void *iph, pbuf_t *pbuf);

extern socket_ops_t g_socket_ops_udp;

#endif