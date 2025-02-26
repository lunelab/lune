/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2024 Lune Reseau, Inc.
 */

#include "lune/mem.h"

#include "net/ip.h"
#include "net/mac.h"
#include "net/pbuf.h"
#include "rt/core.h"

unsigned short pbuf_get_max_hdr_len(lune_id_type_en type, void *entry)
{
    switch (type) {
    case LUNE_ID_NET_IF:
        return 0;
    case LUNE_ID_MAC:
        return mac_get_max_hdr_len((mac_t *)entry);
    case LUNE_ID_IPV4:
        return ipv4_get_max_hdr_len((ip_t *)entry);
    case LUNE_ID_IPV6:
        return ipv6_get_max_hdr_len((ip_t *)entry);
    case LUNE_ID_SOCKET:
        return ((socket_t *)entry)->ops->get_max_hdr_len((socket_t *)entry);
    default:
        lune_assert(0);
        return 0;
    }
}

#ifdef LUNE_BUILD_DPDK
__thread dlist_head_t g_pbuf_dpdk_pbuf_list;

pbuf_t *pbuf_dpdk_alloc_send_pbuf(unsigned short len)
{
    pbuf_t *pbuf;

#ifdef LUNE_DEBUG
    lune_assert(CORE_IS_NP());
#endif

    if (NULL == (pbuf = pbuf_dpdk_get_send_pbuf())) {
        if (NULL == (pbuf = (pbuf_t *)lune_malloc_mt(sizeof(pbuf_t)))) {
            ERR_SET_ERR(LUNE_ERR_NO_MEM);
            return NULL;
        }
    } else {
        /* cached tcp pbuf fetched */
    }

    dlist_init_node(&pbuf->node);
    pbuf->hdr_len = 0;
    pbuf->payload_len = len;
    pbuf->jiffies = TIMER_GET_CURRENT_JIFFIES();
    pbuf->pkt_info = 0;
    pbuf->macp = NULL;
    pbuf->ethh = NULL;
    lune_atomic32_set(&pbuf->ref_cnt, 0);
    if (NULL == (pbuf->mbuf = rte_pktmbuf_alloc(g_net_if_dpdk_send_mbuf_pool))) {
        pbuf_dpdk_cache_send_pbuf(pbuf);
        ERR_SET_ERR(LUNE_ERR_NO_MEM);
        return NULL;
    }
    pbuf->mbuf->data_len = len;

    return pbuf;
}

/*
    release mbuf and cache pbuf for future use
*/
void pbuf_dpdk_free_send_pbuf(pbuf_t *pbuf)
{
#ifdef LUNE_DEBUG
    lune_assert(CORE_IS_NP());
#endif

    if (NULL != pbuf->mbuf) {
        rte_pktmbuf_free(pbuf->mbuf);
        pbuf->mbuf = NULL;
    }

    pbuf_dpdk_cache_send_pbuf(pbuf);
}
#endif

int pbuf_local_init(void)
{
#ifdef LUNE_BUILD_DPDK
    dlist_init_head(&g_pbuf_dpdk_pbuf_list);
#endif
    return 0;
}

void pbuf_local_fini(void)
{
#ifdef LUNE_BUILD_DPDK
    pbuf_t *p, *p2;

    dlist_for_each_node_safe(p, p2, &g_pbuf_dpdk_pbuf_list, node2) {
        dlist_del(&p->node2);
        lune_free_mt(p);
    }
#endif
}
