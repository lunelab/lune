/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2024 Lune Reseau, Inc.
 */

#ifndef __IP_H_PRE__
#define __IP_H_PRE__

#include "lune/ip.h"

typedef struct _ip ip_t;
typedef struct _ip_pcb {
    lune_ip_socket_callback_t cb;
    ip_t *ipp;
} ip_pcb_t;

#endif

#ifndef __IP_H__
#define __IP_H__

#include "lune/id.h"
#include "lune/mem.h"

#include "net/ipv4.h"
#include "net/ipv6.h"
#include "net/mac.h"
#include "net/pbuf.h"

#define IP_GET_LOWER_ENTRY(ipp)             ((ip_t *)(ipp))->lower_entry
#define IP_GET_LOWER_TYPE(ipp)              ((ip_t *)(ipp))->lower_type

#define IP_MAX_PAYLOAD_BUF_SIZE             65536

typedef struct _ip {
    dlist_node_t node;

    lune_ip_stats_t stats;

#define IP_GET_ID(ipp)                      (((struct _ip *)(ipp))->id)
    unsigned int id;
    unsigned int ref_cnt;

    void *lower_entry;
    lune_id_type_en lower_type;

    /* cache socket if any */
    void *sk;
    /*
        cache last tcp listen socket if any, only work
        for single tcp listen socket case
    */
    void *tcp_listen_sk;

#define IP_FLAG_ON(ipp, flag)               (((ip_t *)(ipp))->flags & (flag))
#define IP_SET_FLAG(ipp, flag)              \
    do { ((ip_t *)(ipp))->flags |= (flag); } while (0)
#define IP_CLEAR_FLAG(ipp, flag)            \
    do { ((ip_t *)(ipp))->flags &= (~flag); } while (0)
#define IP_FLAG_SOCKET                      0x00000001
#define IP_IS_SOCKET(ipp)                   IP_FLAG_ON(ipp, IP_FLAG_SOCKET)
#define IP_SET_SOCKET(ipp)                  IP_SET_FLAG(ipp, IP_FLAG_SOCKET)
#define IP_SET_NON_SOCK(ipp)                IP_CLEAR_FLAG(ipp, IP_FLAG_SOCKET)
#define IP_FLAG_DELETE                      0x00000002
#define IP_IS_DELETED(ipp)                  IP_FLAG_ON(ipp, IP_FLAG_DELETE)
#define IP_SET_DELETED(ipp)                 IP_SET_FLAG(ipp, IP_FLAG_DELETE)
#define IP_SET_ADDED(ipp)                   IP_CLEAR_FLAG(ipp, IP_FLAG_DELETE)
/*
    NOTICE:
    
    Ip socket will fail to bind to an ip if the ip has once been bound to L4 socket
    no matter whether the socket still exists or has gone
*/
#define IP_FLAG_L4_SOCKET                   0x00000004
#define IP_L4_SOCKET_EXIST(ipp)             IP_FLAG_ON(ipp, IP_FLAG_L4_SOCKET)
#define IP_SET_L4_SOCKET(ipp)               IP_SET_FLAG(ipp, IP_FLAG_L4_SOCKET)
#define IP_SET_NON_L4_SOCKET(ipp)           IP_CLEAR_FLAG(ipp, IP_FLAG_L4_SOCKET)
#define IP_FLAG_IPV6                        0x00000008
#define IP_IS_IPV6(ipp)                     IP_FLAG_ON(ipp, IP_FLAG_IPV6)
#define IP_SET_IPV6(ipp)                    IP_SET_FLAG(ipp, IP_FLAG_IPV6)
#define IP_SET_IPV4(ipp)                    IP_CLEAR_FLAG(ipp, IP_FLAG_IPV6)
#define IP_FLAG_HW_RX_IP_CSUM               0x00000010
#define IP_IS_HW_RX_IP_CSUM(ipp)            IP_FLAG_ON(ipp, IP_FLAG_HW_RX_IP_CSUM)
#define IP_SET_HW_RX_IP_CSUM(ipp)           IP_SET_FLAG(ipp, IP_FLAG_HW_RX_IP_CSUM)
#define IP_CLEAR_HW_RX_IP_CSUM(ipp)         IP_CLEAR_FLAG(ipp, IP_FLAG_HW_RX_IP_CSUM)
#define IP_FLAG_HW_RX_TCP_CSUM              0x00000020
#define IP_IS_HW_RX_TCP_CSUM(ipp)           IP_FLAG_ON(ipp, IP_FLAG_HW_RX_TCP_CSUM)
#define IP_SET_HW_RX_TCP_CSUM(ipp)          IP_SET_FLAG(ipp, IP_FLAG_HW_RX_TCP_CSUM)
#define IP_CLEAR_HW_RX_TCP_CSUM(ipp)        IP_CLEAR_FLAG(ipp, IP_FLAG_HW_RX_TCP_CSUM)
#define IP_FLAG_HW_RX_UDP_CSUM              0x00000040
#define IP_IS_HW_RX_UDP_CSUM(ipp)           IP_FLAG_ON(ipp, IP_FLAG_HW_RX_UDP_CSUM)
#define IP_SET_HW_RX_UDP_CSUM(ipp)          IP_SET_FLAG(ipp, IP_FLAG_HW_RX_UDP_CSUM)
#define IP_CLEAR_HW_RX_UDP_CSUM(ipp)        IP_CLEAR_FLAG(ipp, IP_FLAG_HW_RX_UDP_CSUM)
#define IP_FLAG_HW_TX_IP_CSUM               0x00000080
#define IP_IS_HW_TX_IP_CSUM(ipp)            IP_FLAG_ON(ipp, IP_FLAG_HW_TX_IP_CSUM)
#define IP_SET_HW_TX_IP_CSUM(ipp)           IP_SET_FLAG(ipp, IP_FLAG_HW_TX_IP_CSUM)
#define IP_CLEAR_HW_TX_IP_CSUM(ipp)         IP_CLEAR_FLAG(ipp, IP_FLAG_HW_TX_IP_CSUM)
#define IP_FLAG_HW_TX_TCP_CSUM              0x00000100
#define IP_IS_HW_TX_TCP_CSUM(ipp)           IP_FLAG_ON(ipp, IP_FLAG_HW_TX_TCP_CSUM)
#define IP_SET_HW_TX_TCP_CSUM(ipp)          IP_SET_FLAG(ipp, IP_FLAG_HW_TX_TCP_CSUM)
#define IP_CLEAR_HW_TX_TCP_CSUM(ipp)        IP_CLEAR_FLAG(ipp, IP_FLAG_HW_TX_TCP_CSUM)
#define IP_FLAG_HW_TX_UDP_CSUM              0x00000200
#define IP_IS_HW_TX_UDP_CSUM(ipp)           IP_FLAG_ON(ipp, IP_FLAG_HW_TX_UDP_CSUM)
#define IP_SET_HW_TX_UDP_CSUM(ipp)          IP_SET_FLAG(ipp, IP_FLAG_HW_TX_UDP_CSUM)
#define IP_CLEAR_HW_TX_UDP_CSUM(ipp)        IP_CLEAR_FLAG(ipp, IP_FLAG_HW_TX_UDP_CSUM)
#define IP_FLAG_ARP_DISABLED                0x00000400
#define IP_IS_ARP_DISABLED(ipp)             IP_FLAG_ON(ipp, IP_FLAG_ARP_DISABLED)
#define IP_SET_ARP_DISABLED(ipp)            IP_SET_FLAG(ipp, IP_FLAG_ARP_DISABLED)
#define IP_SET_ARP_ENABLED(ipp)             IP_CLEAR_FLAG(ipp, IP_FLAG_ARP_DISABLED)
#define IP_FLAG_DPDK                        0x00000800
#define IP_IS_DPDK(ipp)                     IP_FLAG_ON(ipp, IP_FLAG_DPDK)
#define IP_SET_DPDK(ipp)                    IP_SET_FLAG(ipp, IP_FLAG_DPDK)
#define IP_SET_NONDPDK(ipp)                 IP_CLEAR_FLAG(ipp, IP_FLAG_DPDK)
    unsigned int flags;

    union {
        ipv4_t ipv4;
        ipv6_t ipv6;
    };

    /*
        reference count unneeded where ifp applies because:
        1. it is used only for hash/compare
        2. already referenced by mac
    */
    void *ifp;
} ip_t;

#define IP_IS_PAYLOAD_LEN_VALID(ipp, len)   \
    (len <= (IP_IS_IPV6(ipp) ? LUNE_IPV6_MAX_PAYLOAD_LEN : LUNE_IPV4_MAX_PAYLOAD_LEN))

extern __thread void *g_ip_idlist;

extern __thread void *g_ip_idtable;

extern __thread void *g_ip_htable;

ip_t *ip_get_ip_by_addr(void *addr,
    unsigned int is_ipv6, lune_id_type_en lower_type, void *lower_entry, void *ifp);

ip_t *ip_get_ip_by_id(unsigned int id);

void ip_set_net_if_hw_csum_flags(ip_t *ipp);

unsigned short ip_get_mtu(ip_t *ipp);

int ip_local_init(void);

void ip_local_fini(void);

static inline void ip_hold(ip_t *ipp)
{
    ++ipp->ref_cnt;
}

static inline void ip_put(ip_t *ipp)
{
    if (0 == --ipp->ref_cnt) {
        lune_free(ipp);
    }
}

/*
    fragmentation supported
*/
static inline int ip_output(ip_t *ipp, const lune_ip_addr_t *dst_addr, unsigned char proto, pbuf_t *pbuf)
{
    if (unlikely(IP_IS_DELETED(ipp))) {
        lune_assert(NULL == ipp->lower_entry);
        return ERR_SET_ERR(LUNE_ERR_ALREADY_DELETED);
    }

    if (IP_IS_IPV6(ipp)) {
        return ipv6_output(ipp, &dst_addr->ipv6, proto, pbuf);
    } else {
        return ipv4_output(ipp, dst_addr->ipv4, proto, pbuf);
    }
}

/*
    fragmentation not supported
    caller MUST guarantee packet doesn't need fragmentation
*/
static inline int ip_output_nofrag(ip_t *ipp, const lune_ip_addr_t *dst_addr, unsigned char proto, pbuf_t *pbuf)
{
    if (unlikely(IP_IS_DELETED(ipp))) {
        lune_assert(NULL == ipp->lower_entry);
        return ERR_SET_ERR(LUNE_ERR_ALREADY_DELETED);
    }

    if (IP_IS_IPV6(ipp)) {
        return ipv6_output_nofrag(ipp, &dst_addr->ipv6, proto, pbuf);
    } else {
        return ipv4_output_nofrag(ipp, dst_addr->ipv4, proto, pbuf);
    }
}

static inline int ip_get_mac(ip_t *ipp, lune_mac_addr_t mac)
{
    if (ipp->lower_type != LUNE_ID_MAC) {
        return ERR_SET_ERR(LUNE_ERR_NOT_SUPPORTED);
    }

    MAC_GET_MAC(ipp->lower_entry, mac);
    return 0;
}

static inline unsigned int ip_is_pkt_frag(ip_t *ipp, unsigned short len)
{
    if (IP_IS_IPV6(ipp)) {
        return (len + LUNE_IPV6_HDR_LEN + LUNE_IPV6_FRAG_HDR_LEN) > mac_get_mtu(IP_GET_LOWER_ENTRY(ipp));
    } else {
        return (len + LUNE_IPV4_HDR_LEN) > mac_get_mtu(IP_GET_LOWER_ENTRY(ipp));
    }
}

static inline void ip_conv_ip(ip_t *ipp, lune_ip_addr_t *addr)
{
    addr->is_ipv6 = !!IP_IS_IPV6(ipp);
    if (IP_IS_IPV6(ipp)) {
        LUNE_IPV6_CPY(&addr->ipv6, &ipp->ipv6.ip);
    } else {
        addr->ipv4 = ipp->ipv4.ip;
    }
}

extern socket_ops_t g_socket_ops_ip;

#endif