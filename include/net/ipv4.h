/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2024 Lune Reseau, Inc.
 */

#ifndef __IPV4_H_PRE__
#define __IPV4_H_PRE__

#include "lune/igmp.h"
#include "lune/ipv4.h"
#include "lune/list.h"

typedef struct _ipv4 ipv4_t;
typedef struct _ipv4_pcb {
    lune_ipv4_socket_callback_t cb;
    ip_t *ipv4p;
} ipv4_pcb_t;

#endif

#ifndef __IPV4_H__
#define __IPV4_H__

#include "net/ipv6.h"
#include "net/pbuf.h"
#include "net/socket.h"

#define IPV4_GET_HDR_LEN(ipv4h)                 \
    ((0x0f & ((const lune_ipv4_hdr_t *)(ipv4h))->ver_len) << 2)
#define IPV4_IS_SAME_SUBNET(ip1, ip2, mask)     (((ip1) & (mask)) == ((ip2) & (mask)))
#define IPV4_IS_BROADCAST_IN_SUBNET(ip, mask)   \
    ((((ip) & ~(mask)) | (mask)) == LUNE_BROADCAST_IPV4)
#define IPV4_IS_BROADCAST_IP(ip)                (LUNE_BROADCAST_IPV4 == (ip))
#define IPV4_IS_MULTICAST_IP(ip)                (((ip) & 0xf0000000) == 0xe0000000)

typedef struct _gateway {
    dlist_node_t node;
    lune_ipv4_addr_t dst;
    lune_ipv4_addr_t mask;
    lune_ipv4_addr_t gw;
} gateway_t;

typedef struct _ipv4 {
    lune_ipv4_addr_t ip;
    lune_ipv4_addr_t mask;
    lune_ipv4_addr_t gw;
    /* gateway list */
    dlist_head_t gw_list;
    unsigned short pkt_id;
} ipv4_t;

int ipv4_local_init(void);
void ipv4_local_fini(void);

int ipv4_join_group(ip_t *ipv4p, const lune_ipv4_join_group_arg_t *arg);
int ipv4_leave_group(ip_t *ipv4p, lune_ipv4_addr_t group_addr);

int ipv4_input(lune_id_type_en lower_type, void *lower_entry, pbuf_t *pbuf);

unsigned short ipv4_get_max_hdr_len(ip_t *ipv4p);

int ipv4_output(ip_t *ipv4p,
    lune_ipv4_addr_t dst_addr, unsigned char proto, pbuf_t *pbuf);

int ipv4_output_nofrag(ip_t *ipv4p,
    lune_ipv4_addr_t dst_addr, unsigned char proto, pbuf_t *pbuf);

extern socket_ops_t g_socket_ops_ipv4;

#endif