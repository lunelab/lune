/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2024 Lune Reseau, Inc.
 */

#ifndef __NB_H__
#define __NB_H__

#define NB_RETRIEVE_SUCCESS         (0)
#define NB_PKT_QUEUEING             (1)

#include "lune/ip.h"
#include "lune/list.h"
#include "lune/mac.h"
#include "lune/timer.h"

#include "net/ip.h"
#include "net/mac.h"
#include "net/pbuf.h"

typedef struct _neighbor {
    dlist_node_t node;
    dlist_head_t pbuf_list;
    /* timer is shared by expired nb cache and nb request timeout */
    lune_timer_t tmr;
    /* ipp is only used at NB_STATE_REQ state */
    ip_t *ipp;
    lune_mac_addr_t dst_mac;
    unsigned short retrans;
    lune_ip_addr_t dst_addr;
#define NB_STATE_REQ            (0)
#define NB_STATE_ALIVE          (1)
    unsigned short state;
    unsigned short queue_pkt_cnt;
    unsigned int ref_cnt;
    /*
        reference count unneeded where ifp applies because:
        1. it is used only for hash/compare
        2. already referenced by mac
    */
    void *ifp;
} neighbor_t;

#define NB_IS_REQUESTING(nb)    \
    (NB_STATE_REQ == ((neighbor_t *)nb)->state || ((neighbor_t *)nb)->queue_pkt_cnt > 0)

#define NB_GET_MAC(nb)          (((neighbor_t *)nb)->dst_mac)

void *nb_lookup(const lune_ip_addr_t *addr, void *ifp);
/*
    update if exist or insert a new neighbor (inbound only)
*/
int nb_upsert(const lune_mac_addr_t dst_mac, lune_ip_addr_t *dst_addr, void *ifp);
void nb_delete(void *nb);

/*
    create a new neighbor (outbound only)
    caller MUST guarantee it doesn't exist in neighbor table
*/
int nb_request_and_cache_pkt(const lune_ip_addr_t *dst_addr,
    ip_t *ipp, mac_t *macp, pbuf_t *pbuf);
int nb_cache_pkt(void *nb, mac_t *macp, pbuf_t *pbuf);

void nb_log_error(const char *msg, const lune_ip_addr_t *addr, int err);

int nb_local_init(void);
void nb_local_fini(void);

#endif