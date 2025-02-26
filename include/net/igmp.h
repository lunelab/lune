/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2024 Lune Reseau, Inc.
 */

#ifndef __IGMP_H_PRE__
#define __IGMP_H_PRE__

#include "lune/igmp.h"
#include "lune/ip.h"
#include "lune/list.h"

#include "net/ip.h"

typedef struct _igmp_pcb {
    lune_igmp_socket_callback_t cb;
    ip_t *ipv4p;
    dlist_node_t node;
    lune_ipv4_addr_t group_addr;
} igmp_pcb_t;

#endif

#ifndef __IGMP_H__
#define __IGMP_H__

#include "net/mac.h"
#include "net/pbuf.h"
#include "net/socket.h"

#define igmp_group_for_each_host_group(ihgp, igp)       \
    dlist_for_each_node(ihgp, &(igp)->host_group_list, node2)

typedef struct _igmp_group {
    dlist_node_t node;
    dlist_head_t host_group_list;
    void *host_group_htable;
    lune_ipv4_addr_t group_addr;
    unsigned int host_cnt;
    unsigned int igmp_socket_cnt;
    lune_timer_t delay_report_tmr;
} igmp_group_t;

typedef struct _igmp_host_group {
    dlist_node_t node;      /* host group hash table */
    dlist_node_t node2;     /* host group link list */
    dlist_head_t igmp_socket_list;    /* igmp socket link list */
    dlist_head_t udp_socket_list;     /* udp socket link list */
    ip_t *ipv4p;
    igmp_group_t *igp;
    lune_igmp_version_en ver;
} igmp_host_group_t;

int igmp_local_init(void);
void igmp_local_fini(void);

int igmp_input(igmp_group_t *igp, lune_ipv4_hdr_t *ipv4h, pbuf_t *pbuf);

int igmp_join_group(ip_t *ipv4p, lune_ipv4_addr_t group_addr, lune_igmp_version_en ver);
int igmp_leave_group(ip_t *ipv4p, lune_ipv4_addr_t group_addr);
igmp_group_t *igmp_find_group(lune_ipv4_addr_t group_addr);

extern socket_ops_t g_socket_ops_igmp;

#endif