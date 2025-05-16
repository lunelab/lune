/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2024 Lune Reseau, Inc.
 */

#include "lune/arp.h"
#include "lune/list.h"
#include "lune/log.h"

#include "net/arp.h"
#include "net/ip.h"
#include "net/mac.h"
#include "net/nb.h"
#include "net/pbuf.h"

static inline int arp_output(const lune_mac_addr_t dst_mac, 
    mac_t *macp,
    unsigned int dst_addr,
    unsigned int src_addr,
    unsigned short hard_type,
    unsigned short proto,
    unsigned short op_code)
{
    unsigned char lbuf[PBUF_MAX_RSVD_HDR_LEN];
    pbuf_t pbuf;
    lune_arp_hdr_t *arph;

    pbuf_init_send_pbuf(&pbuf, lbuf, 0, PBUF_MAX_RSVD_HDR_LEN, MAC_IS_DPDK(macp));

    arph = (lune_arp_hdr_t *)pbuf_move_down(&pbuf, LUNE_ARP_HDR_LEN);
    arph->hard_type = lune_htons(hard_type);
    arph->proto = lune_htons(proto);
    arph->mac_len = LUNE_MAC_ADDR_LEN;
    arph->ipv4_len = LUNE_IPV4_ADDR_LEN;
    arph->op_code = op_code;
    LUNE_MAC_CPY(arph->src_mac, macp->mac);
    arph->src_addr = lune_htonl(src_addr);
    if (op_code == LUNE_ARP_REQ) {
        LUNE_MAC_CPY(arph->dst_mac, g_all_zero_mac);
    } else {
        LUNE_MAC_CPY(arph->dst_mac, dst_mac);
    }
    arph->op_code = lune_htons(arph->op_code);
    arph->dst_addr = lune_htonl(dst_addr);

    return mac_output(macp, dst_mac, ETH_TYPE_ARP_N, &pbuf);
}

int arp_send_req(ip_t *ipv4p, lune_ipv4_addr_t dst_addr)
{
    return arp_output(g_broadcast_mac, ipv4p->lower_entry, dst_addr,
        ipv4p->ipv4.ip, LUNE_HW_TYPE_ETHERNET, LUNE_ETH_TYPE_IPV4, LUNE_ARP_REQ);
}

int arp_input(mac_t *macp, pbuf_t *pbuf)
{
    ip_t *ipv4p;
    lune_arp_hdr_t *arph = (lune_arp_hdr_t*)pbuf->payload;
    int err;
    unsigned int dst_addr = lune_ntohl(arph->dst_addr);
    unsigned int src_addr = lune_ntohl(arph->src_addr);
    char ipv4_str[LUNE_IPV4_MAX_ADDR_STR_LEN];
    char mac_str[LUNE_MAC_ADDR_STR_LEN], mac_str2[LUNE_MAC_ADDR_STR_LEN];
    lune_ip_addr_t addr;

    switch (lune_ntohs(arph->op_code)) {
    case LUNE_ARP_REQ:
        /* one ip can be bound to only one mac on an interface */
        if (NULL == (ipv4p = ip_get_ip_by_addr((void *)&dst_addr,
            0, LUNE_ID_MAC, NULL, NET_IF_GET_CURR_NET_IF()))) {
            if (src_addr == dst_addr) {
                /* gratuitous arp */
                addr.is_ipv6 = 0;
                addr.ipv4 = src_addr;
                if (0 != (err = nb_upsert(arph->src_mac, &addr, NET_IF_GET_CURR_NET_IF()))) {
                    nb_log_error("failed to upsert neighbor", &addr, err);
                    return err;
                }
            }

            return 0;
        }

        addr.is_ipv6 = 0;
        addr.ipv4 = src_addr;
        if (src_addr == dst_addr) {
            /*
                It may occur for gratuitous arp if it's a loopback packet
            */
            if (0 != (err = nb_upsert(arph->src_mac, &addr, NET_IF_GET_CURR_NET_IF()))) {
                nb_log_error("failed to upsert neighbor", &addr, err);
                return err;
            }

            return 0;
        }

        lune_assert(ipv4p->lower_entry != NULL);

        if (0 != (err = nb_upsert(arph->src_mac, &addr, NET_IF_GET_CURR_NET_IF()))) {
            nb_log_error("failed to upsert neighbor", &addr, err);
            return err;
        }

        if (!IP_IS_ARP_DISABLED(ipv4p)) {
            if (0 != (err = arp_output(arph->src_mac, ipv4p->lower_entry, src_addr, ipv4p->ipv4.ip, 
                LUNE_HW_TYPE_ETHERNET, LUNE_ETH_TYPE_IPV4, LUNE_ARP_RESP))) {
                lune_log(LUNE_WARN, "failed to reply to arp request for %s",
                    lune_ipv4_to_str(ipv4p->ipv4.ip, ipv4_str, LUNE_IPV4_MAX_ADDR_STR_LEN));
            }
        }

        return err;
    case LUNE_ARP_RESP:
        /* one ip can be bound to only one mac on an interface */
        if (NULL == (ipv4p = ip_get_ip_by_addr((void *)&dst_addr,
            0, LUNE_ID_MAC, NULL, NET_IF_GET_CURR_NET_IF()))) {
            if (src_addr == dst_addr) {
                /* gratuitous arp */
                addr.is_ipv6 = 0;
                addr.ipv4 = src_addr;
                if (0 != (err = nb_upsert(arph->src_mac, &addr, NET_IF_GET_CURR_NET_IF()))) {
                    nb_log_error("failed to upsert neighbor", &addr, err);
                    return err;
                }
            }

            return 0;
        }

        if (likely(macp != NULL)
            && unlikely(macp != ipv4p->lower_entry)) {
            lune_log(LUNE_INFO, "ip and mac mismatched in arp response: "
                "ip %s with mac %s, but mac %s expected",
                lune_ipv4_to_str(ipv4p->ipv4.ip, ipv4_str, LUNE_IPV4_MAX_ADDR_STR_LEN),
                lune_mac_to_str(macp->mac, mac_str, LUNE_MAC_ADDR_STR_LEN),
                lune_mac_to_str(((mac_t *)ipv4p->lower_entry)->mac, mac_str2, LUNE_MAC_ADDR_STR_LEN));
            return ERR_SET_ERR(LUNE_ERR_ARP_UNEXPECTED_PKT);
        }

        lune_assert(NULL != ipv4p->lower_entry);

        addr.is_ipv6 = 0;
        addr.ipv4 = src_addr;
        if (0 != (err = nb_upsert(arph->src_mac,
            &addr, NET_IF_GET_CURR_NET_IF()))) {
            nb_log_error("failed to upsert neighbor", &addr, err);
        }

        return err;
    default:
        lune_log(LUNE_INFO, "received unexpected opcode %d for arp packet", arph->op_code);
        return ERR_SET_ERR(LUNE_ERR_NOT_SUPPORTED);
    }
}

int ipv4_route(mac_t *macp, lune_mac_addr_t dst_mac,
    ip_t *ipv4p, lune_ipv4_addr_t dst_addr, pbuf_t *pbuf)
{
    void *nb;
    gateway_t *gw;
    int err;
    lune_ip_addr_t addr;

    if (IPV4_IS_SAME_SUBNET(ipv4p->ipv4.ip, dst_addr, ipv4p->ipv4.mask)) {
        if (IPV4_IS_BROADCAST_IN_SUBNET(dst_addr, ipv4p->ipv4.mask)) {
            /* broadcast in subnet */
            LUNE_MAC_CPY(dst_mac, g_broadcast_mac);
            return NB_RETRIEVE_SUCCESS;
        }
        goto SEARCH_DST_IP;
    }

    dlist_for_each_node(gw, &ipv4p->ipv4.gw_list, node){
        if (IPV4_IS_SAME_SUBNET(gw->dst, dst_addr, gw->mask)) {
            dst_addr = gw->gw;
            goto SEARCH_DST_IP;
        }
    }

    dst_addr = ipv4p->ipv4.gw;

SEARCH_DST_IP:
    addr.is_ipv6 = 0;
    addr.ipv4 = dst_addr;
    if (NULL == (nb = nb_lookup(&addr, ipv4p->ifp))) {
        /* send arp request and put packet on hold till response received */
        if (0 != (err = nb_request_and_cache_pkt(&addr, ipv4p, macp, pbuf))) {
            return err;
        }

        return NB_PKT_QUEUEING;
    }

    if (NB_IS_REQUESTING(nb)) {
        /* arp request already sent but still waiting for response */
        if (0 != (err = nb_cache_pkt(nb, macp, pbuf))) {
            return err;
        }

        return NB_PKT_QUEUEING;
    }

    LUNE_MAC_CPY(dst_mac, NB_GET_MAC(nb));
    return NB_RETRIEVE_SUCCESS;
}

int lune_send_grat_arp(unsigned int ip_id)
{
    ip_t *ipv4p;

    if (LUNE_INVALID_ID == ip_id) {
        return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
    }

    if (NULL == (ipv4p = ip_get_ip_by_id(ip_id))) {
        return ERR_SET_ERR(LUNE_ERR_ID_NOT_FOUND);
    }

    if (LUNE_ID_MAC != ipv4p->lower_type) {
        return ERR_SET_ERR(LUNE_ERR_NOT_SUPPORTED);
    }

    return arp_output(g_broadcast_mac, (mac_t *)ipv4p->lower_entry, ipv4p->ipv4.ip, ipv4p->ipv4.ip,
        LUNE_HW_TYPE_ETHERNET, LUNE_ETH_TYPE_IPV4, LUNE_ARP_REQ);
}
