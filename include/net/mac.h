/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2024 Lune Reseau, Inc.
 */

#ifndef __MAC_H_PRE__
#define __MAC_H_PRE__

#include "lune/mac.h"

typedef struct _mac mac_t;
typedef struct _mac_pcb {
    lune_mac_socket_callback_t cb;
    mac_t *macp;
} mac_pcb_t;

#endif

#ifndef __MAC_H__
#define __MAC_H__

#include "net/pbuf.h"
#include "net/socket.h"

#define ETH_TYPE_ARP_N                              0x0608
#define ETH_TYPE_IPV4_N                             0x0008
#define ETH_TYPE_IPV6_N                             0xdd86
#define ETH_TYPE_VLAN_N                             0x0081

#define MAC_GET_LOWER_ENTRY(macp)                   ((mac_t *)(macp))->lower_entry
#define MAC_GET_LOWER_TYPE(macp)                    ((mac_t *)(macp))->lower_type
#define MAC_GET_MAC(macp, mac)                      \
    LUNE_MAC_CPY(mac, ((mac_t *)(macp))->mac)

#ifdef LUNE_BIG_ENDIAN
#define MAC_MULTICAST_MS_25_BIT                     (0x01005e7f)
#else
#define MAC_MULTICAST_MS_25_BIT                     (0x7f5e0001)
#endif

#define MAC_GET_IPV4_MC_MAC(mc, mac)                \
    do {                                            \
        lune_ipv4_addr_t n_mc = lune_ntohl(mc);     \
        *(unsigned int *)(unsigned char *)(mac) = MAC_MULTICAST_MS_25_BIT;  \
        (mac)[3] = ((unsigned char *)&n_mc)[1] & (mac)[3];                  \
        *(unsigned short *)(((unsigned char *)(mac)) + 4)                   \
            = *(unsigned short *)((unsigned char *)&n_mc + 2);              \
    } while (0)

#define MAC_GET_IPV6_MC_MAC(mc, mac)                \
    do {                                            \
        *(unsigned short *)(unsigned char *)(mac) = 0x3333;                 \
        *(unsigned int *)((unsigned char *)(mac) + 2)                       \
            = ((const lune_ipv6_addr_t *)(mc))->addr[3];                          \
    } while (0)

extern const lune_mac_addr_t g_broadcast_mac;
extern const lune_mac_addr_t g_all_zero_mac;

typedef struct _mac {
    dlist_node_t node;

    lune_mac_stats_t stats;

    unsigned int id;
    unsigned int ref_cnt;

    lune_mac_addr_t mac;

    unsigned short mtu;

    void *lower_entry;
    lune_id_type_en lower_type;

    /* both outer_vid and inner_vid ranges from 0x000 to 0xfff */
    unsigned short outer_vid;
    unsigned short inner_vid;

#define MAC_FLAG_ON(macp, flag)         (((mac_t *)(macp))->flags & (flag))
#define MAC_SET_FLAG(macp, flag)        \
    do { ((mac_t *)(macp))->flags |= (flag); } while (0)
#define MAC_CLEAR_FLAG(macp, flag)      \
    do { ((mac_t *)(macp))->flags &= (~flag); } while (0)
#define MAC_MASK_VLAN_TYPE              0x00000003
#define MAC_VLAN_TYPE_NONE              0x00000000
#define MAC_VLAN_TYPE_VLAN              0x00000001
#define MAC_VLAN_TYPE_QINQ              0x00000002
#define MAC_GET_VLAN_TYPE(macp)         \
    (((mac_t *)(macp))->flags & MAC_MASK_VLAN_TYPE)
#define MAC_SET_VLAN_TYPE(macp, type)   \
    do { ((mac_t *)(macp))->flags &= ~MAC_MASK_VLAN_TYPE;   \
        ((mac_t *)(macp))->flags |= (type); } while (0)
#define MAC_SET_VLAN_NONE(macp)         \
    MAC_SET_VLAN_TYPE(macp, MAC_VLAN_TYPE_NONE)
#define MAC_SET_VLAN_VLAN(macp)         \
    MAC_SET_VLAN_TYPE(macp, MAC_VLAN_TYPE_VLAN)
#define MAC_SET_VLAN_QINQ(macp)         \
    MAC_SET_VLAN_TYPE(macp, MAC_VLAN_TYPE_QINQ)
#define MAC_FLAG_ACTIVE                 0x00000004
#define MAC_IS_ACTIVE(macp)             MAC_FLAG_ON(macp, MAC_FLAG_ACTIVE)
#define MAC_SET_ACTIVE(macp)            MAC_SET_FLAG(macp, MAC_FLAG_ACTIVE)
#define MAC_SET_INACTIVE(macp)          MAC_CLEAR_FLAG(macp, MAC_FLAG_ACTIVE)
#define MAC_FLAG_SOCKET                 0x00000008
#define MAC_IS_SOCKET(macp)             MAC_FLAG_ON(macp, MAC_FLAG_SOCKET)
#define MAC_SET_SOCKET(macp)            MAC_SET_FLAG(macp, MAC_FLAG_SOCKET)
#define MAC_SET_NONSOCK(macp)           MAC_CLEAR_FLAG(macp, MAC_FLAG_SOCKET)
#define MAC_FLAG_DPDK                   0x00000010
#define MAC_IS_DPDK(macp)               MAC_FLAG_ON(macp, MAC_FLAG_DPDK)
#define MAC_SET_DPDK(macp)              MAC_SET_FLAG(macp, MAC_FLAG_DPDK)
#define MAC_SET_NONDPDK(macp)           MAC_CLEAR_FLAG(macp, MAC_FLAG_DPDK)
    unsigned int flags;

    /* cache mac socket if any */
    void *sk;
} mac_t;

int mac_local_init(void);

void mac_local_fini(void);

static inline void mac_hold(mac_t *macp)
{
    ++macp->ref_cnt;
}

static inline void mac_put(mac_t *macp)
{
    if (0 == --macp->ref_cnt) {
        lune_free(macp);
    }
}

static inline unsigned short mac_get_mtu(mac_t *macp)
{
    return macp->mtu;
}

int mac_input(void *lower_entry, lune_id_type_en lower_type, pbuf_t *pbuf);

int mac_output(mac_t *macp,
    const lune_mac_addr_t dst_mac, unsigned short type_n, pbuf_t *pbuf);

unsigned short mac_get_max_hdr_len(mac_t *macp);

mac_t *mac_get_mac(unsigned int id);

extern socket_ops_t g_socket_ops_mac;

#endif