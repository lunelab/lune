/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2024 Lune Reseau, Inc.
 */

#include "lune/assert.h"
#include "lune/conv.h"
#include "lune/id.h"
#include "lune/log.h"
#include "lune/mem.h"
#include "lune/net.h"

#include "kernel/sched.h"
#include "lib/htable.h"
#include "lib/idlist.h"
#include "lib/idtable.h"
#include "net/arp.h"
#include "net/id.h"
#include "net/mac.h"
#include "net/socket.h"

#define MAC_VID_MASK                (0xfff)
#define MAC_GET_VID(vf)             \
    (lune_htons(lune_ntohs(((lune_vlan_field_t *)(vf))->tci) & MAC_VID_MASK))

#define IS_MAC_IPV4_MULTICAST(mac)  \
    ((mac[0]== 0x01) && (mac[1] == 0x00) && (mac[2] == 0x5e))
#define IS_MAC_IPV6_MULTICAST(mac)  ((mac[0]== 0x33) && (mac[1] == 0x33))

#define IS_MAC_BROADCAST(mac)       (!LUNE_MAC_CMP(mac, g_broadcast_mac))

#define MAC_HTABLE_SIZE_IN_BIT      (20)
#define MAC_HTABLE_SIZE             (1 << (MAC_HTABLE_SIZE_IN_BIT))
#define MAC_HTABLE_MASK             (MAC_HTABLE_SIZE - 1)

const lune_mac_addr_t g_all_zero_mac = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

const lune_mac_addr_t g_broadcast_mac = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

/*
    NOTICE:

    Mac address over interface (not over socket) is unique per core
    as it is stored in thread-local global hash table. Therefore,
    adding duplicate mac will fail if:
    1. on same interface as first mac
    2. on interface different from the one where first mac resides if
       both interfaces run on same core
*/

static __thread void *s_mac_idlist = NULL;

static __thread void *s_mac_idtable = NULL;

static __thread void *s_mac_htable = NULL;

mac_t *mac_get_mac(unsigned int id)
{
    lune_assert(LUNE_INVALID_ID != id);

    return idtable_find(id, s_mac_idtable);
}

static inline unsigned int mac_add_mac(const lune_mac_addr_t mac,
    lune_id_type_en sub_type,
    void *sub_entry,
    unsigned short outer_vid,
    unsigned short inner_vid)
{
    mac_t *macp;

    lune_assert(NULL != sub_entry);

    if (NULL == (macp = lune_malloc(sizeof(mac_t)))) {
        goto ERR_1;
    }

    if (LUNE_INVALID_ID == (macp->id = idlist_get_new_id(s_mac_idlist))) {
        goto ERR_2;
    }

    if (0 != idtable_insert(macp->id, macp, s_mac_idtable)) {
        goto ERR_3;
    }

    LUNE_MAC_CPY(macp->mac, mac);
    macp->sub_entry = sub_entry;
    macp->sub_type = sub_type;
    macp->outer_vid = lune_htons(outer_vid);
    macp->inner_vid = lune_htons(inner_vid);

    if (0 != htable_insert((void *)macp, s_mac_htable, 0)) {
        goto ERR_4;
    }

    memset(&macp->stats, 0x00, sizeof(lune_mac_stats_t));
    macp->ref_cnt = 0;
    macp->mtu = NET_IF_GET_MTU(sub_entry);
    macp->flags = 0;
    if (LUNE_MAC_VID_NONE == outer_vid) {
        MAC_SET_VLAN_NONE(macp);
    } else if (LUNE_MAC_VID_NONE == inner_vid) {
        MAC_SET_VLAN_VLAN(macp);
    } else {
        MAC_SET_VLAN_QINQ(macp);
    }
    macp->sk = NULL;

    if (LUNE_ID_NET_IF == sub_type) {
        net_if_hold(sub_entry);
#ifdef LUNE_BUILD_DPDK
        if (sub_entry_is_dpdk(sub_entry, sub_type)) {
            MAC_SET_DPDK(macp);
        }
#endif
    }

    /* referenced by id table */
    mac_hold(macp);

    /* referenced by hash table */
    mac_hold(macp);

    return macp->id;

ERR_4:
    lune_assert(idtable_remove(macp->id, s_mac_idtable));

ERR_3:
    lune_assert(!idlist_del_id(macp->id, s_mac_idlist));

ERR_2:
    lune_free(macp);

ERR_1:
    return LUNE_INVALID_ID;
}

static inline int mac_del_mac(mac_t *macp)
{
    int err;

    lune_assert(NULL != macp);

    if (MAC_IS_ACTIVE(macp)) {
        /* disable mac */
        /*
            if LUNE_SOCKET_MAC socket has been created, it must be closed before being disabled
        */
        if (MAC_IS_SOCKET(macp)) {
            return ERR_SET_ERR(LUNE_ERR_NOT_CLOSED);
        }

        MAC_SET_INACTIVE(macp);
    } else {
        lune_assert(!MAC_IS_SOCKET(macp));
    }

    if (0 != (err = htable_remove((void *)macp, s_mac_htable))) {
        return err;
    }

    if (0 != (err = idtable_remove(macp->id, s_mac_idtable))) {
        return err;
    }
    lune_assert(!idlist_del_id(macp->id, s_mac_idlist));

    /* de-referenced from hash table */
    mac_put(macp);

    /* de-referenced from id table */
    mac_put(macp);

    if (LUNE_ID_NET_IF == macp->sub_type) {
        net_if_put(macp->sub_entry);
    }

    return 0;
}

static void mac_idtable_free(mac_t *macp)
{
    lune_assert(!MAC_IS_ACTIVE(macp));

    lune_assert(!idlist_del_id(macp->id, s_mac_idlist));

    mac_put(macp);
}

static void mac_htable_free(mac_t *macp)
{
    if (unlikely(MAC_IS_SOCKET(macp))) {
        lune_log(LUNE_DBG, "mac socket not closed on mac %d", macp->id);
    }

    if (unlikely(MAC_IS_ACTIVE(macp))) {
        lune_log(LUNE_DBG, "mac %d not disabled", macp->id);
        MAC_SET_INACTIVE(macp);
    }

    lune_log(LUNE_DBG, "mac %d not closed", macp->id);

    mac_put(macp);
}

static int mac_htable_hash(mac_t *macp)
{
    return (lune_htonl(*(unsigned int *)(&macp->mac[2])) & MAC_HTABLE_MASK);
}

static int mac_htable_compare(mac_t *macp1, mac_t *macp2)
{
    return  (!((!LUNE_MAC_CMP(macp1->mac, macp2->mac))
        && macp1->outer_vid == macp2->outer_vid
        && macp1->inner_vid == macp2->inner_vid
        && macp1->sub_type == macp2->sub_type
        && macp1->sub_entry == macp2->sub_entry));
}

int mac_local_init(void)
{
    if (NULL == (s_mac_idlist = idlist_create_list("mac id list"))) {
        goto ERR_1;
    }

    if (NULL == (s_mac_idtable = idtable_create_table("mac id table",
        (idtable_free_func_t)mac_idtable_free,
        IDTABLE_MAX_TABLE_SIZE))) {
        goto ERR_2;
    }

    if (NULL == (s_mac_htable = htable_create_table("mac hash table",
        (htable_hash_func_t)mac_htable_hash,
        (htable_compare_func_t)mac_htable_compare,
        (htable_free_func_t)mac_htable_free,
        offsetof(mac_t, node),
        MAC_HTABLE_SIZE,
        0))) {
        goto ERR_3;
    }

    return 0;

ERR_3:
    lune_assert(!idtable_delete_table(s_mac_idtable));
    s_mac_idtable = NULL;

ERR_2:
    lune_assert(!idlist_delete_list(s_mac_idlist));
    s_mac_idlist = NULL;

ERR_1:
    return ERR_GET_LAST_ERR();
}

void mac_local_fini(void)
{
    lune_assert(!htable_delete_table(s_mac_htable));
    s_mac_htable = NULL;

    lune_assert(!idtable_delete_table(s_mac_idtable));
    s_mac_idtable = NULL;

    lune_assert(!idlist_delete_list(s_mac_idlist));
    s_mac_idlist = NULL;
}

int mac_input(void *sub_entry, lune_id_type_en sub_type, pbuf_t *pbuf)
{
    mac_t *macp;
    mac_t m;
    lune_eth_hdr_t *ethh;
    lune_vlan_field_t *vf1, *vf2;
    unsigned short type;
    unsigned short len, hdr_len;

    ethh = (lune_eth_hdr_t *)PBUF_GET_PAYLOAD(pbuf);
    type = lune_ntohs(ethh->type);
    len = PBUF_GET_PAYLOAD_LEN(pbuf);
    hdr_len = LUNE_ETH_HDR_LEN;

    LUNE_MAC_CPY(m.mac, ethh->dst_mac);
    m.sub_entry = sub_entry;
    m.sub_type = sub_type;
    if (LUNE_ETH_TYPE_VLAN == type) {
        vf1 = (lune_vlan_field_t *)&ethh->type;
        m.outer_vid = MAC_GET_VID(vf1);
        type = lune_ntohs(*(unsigned short *)vf1->data);
        hdr_len += LUNE_VLAN_FIELD_LEN;
        if (LUNE_ETH_TYPE_VLAN == type) {
            vf2 = (lune_vlan_field_t *)vf1->data;
            m.inner_vid = MAC_GET_VID(vf2);
            type = lune_ntohs(*(unsigned short *)vf2->data);
            hdr_len += LUNE_VLAN_FIELD_LEN;
        } else {
            m.inner_vid = LUNE_MAC_VID_NONE;
        }
    } else {
        m.outer_vid = m.inner_vid = LUNE_MAC_VID_NONE;
    }

    if (NULL == (macp = htable_find((void *)&m, s_mac_htable))) {
        if (!IS_MAC_BROADCAST(ethh->dst_mac)
            && !IS_MAC_IPV4_MULTICAST(ethh->dst_mac)
            && !IS_MAC_IPV6_MULTICAST(ethh->dst_mac)) {
            return 0;
        }
    } else {
        if (unlikely(!MAC_IS_ACTIVE(macp))) {
            return ERR_SET_ERR(LUNE_ERR_MAC_INTERNAL);
        }

        macp->stats.pkt_in++;
        macp->stats.byte_in += len;

        if (MAC_IS_SOCKET(macp)) {
            mac_pcb_t *pcb;

            lune_assert(NULL != macp->sk);
            pcb = &((socket_t *)macp->sk)->pcb.mac;
            if (unlikely(NULL == pcb->cb.recv)) {
                /*
                    once a socket is bound to a specific mac address without setting
                    receive callback function, all packets on that mac address will
                    be bypassed.
                */
                lune_log(LUNE_INFO, "receive callback function not set"
                    " for mac socket %d", pcb->macp->id);
                return 0;
            }

            pcb->cb.recv(pcb->cb.data, (const unsigned char *)ethh, len);
            return 0;
        }
    }

    (void)pbuf_move_up(pbuf, hdr_len);

    switch (type) {
    case LUNE_ETH_TYPE_IPV4:
        return ipv4_input(LUNE_ID_MAC, macp, pbuf);
    case LUNE_ETH_TYPE_IPV6:
        return ipv6_input(LUNE_ID_MAC, macp, pbuf);
    case LUNE_ETH_TYPE_ARP:
        return arp_input(macp, pbuf);
    default:
        /* warning */
        break;
    }

    return 0;
}

int mac_output(mac_t *macp,
    const lune_mac_addr_t dst_mac, unsigned short type_n, pbuf_t *pbuf)
{
    lune_eth_hdr_t *ethh;
    lune_vlan_field_t *vf;

    if (unlikely(!MAC_IS_ACTIVE(macp))) {
        return ERR_SET_ERR(LUNE_ERR_MAC_INACTIVE);
    }

    switch (MAC_GET_VLAN_TYPE(macp)) {
    case MAC_VLAN_TYPE_NONE:
        pbuf->l2_len = LUNE_ETH_HDR_LEN;
        ethh = (lune_eth_hdr_t *)pbuf_move_down(pbuf, pbuf->l2_len);
        LUNE_MAC_CPY(ethh->dst_mac, dst_mac);
        LUNE_MAC_CPY(ethh->src_mac, macp->mac);
        ethh->type = type_n;
        break;
    case MAC_VLAN_TYPE_VLAN:
        pbuf->l2_len = LUNE_ETH_HDR_LEN + LUNE_VLAN_FIELD_LEN;
        ethh = (lune_eth_hdr_t *)pbuf_move_down(pbuf, pbuf->l2_len);
        LUNE_MAC_CPY(ethh->dst_mac, dst_mac);
        LUNE_MAC_CPY(ethh->src_mac, macp->mac);
        vf = (lune_vlan_field_t *)&ethh->type;
        vf->type = ETH_TYPE_VLAN_N;
        vf->tci = macp->outer_vid;
        *(unsigned short *)vf->data = type_n;
        break;
    case MAC_VLAN_TYPE_QINQ:
        pbuf->l2_len = LUNE_ETH_HDR_LEN + LUNE_QINQ_FIELD_LEN;
        ethh = (lune_eth_hdr_t *)pbuf_move_down(pbuf, pbuf->l2_len);
        LUNE_MAC_CPY(ethh->dst_mac, dst_mac);
        LUNE_MAC_CPY(ethh->src_mac, macp->mac);
        vf = (lune_vlan_field_t *)&ethh->type;
        vf->type = ETH_TYPE_VLAN_N;
        vf->tci = macp->outer_vid;
        vf = (lune_vlan_field_t *)vf->data;
        vf->type = ETH_TYPE_VLAN_N;
        vf->tci = macp->inner_vid;
        *(unsigned short *)vf->data = type_n;
        break;
    default:
        lune_assert(0);
        return ERR_SET_ERR(LUNE_ERR_INTERNAL);
    }

    lune_assert(PBUF_GET_PAYLOAD_LEN(pbuf) <= macp->mtu);

    return net_if_send_pkt(macp->sub_entry, pbuf);
}

unsigned int lune_add_mac(const lune_mac_addr_t mac,
    lune_id_type_en sub_type, unsigned int sub_id)
{
    void *sub_entry;

    SCHED_CHECK_POINT();

    if (NULL == mac
        || LUNE_INVALID_ID == sub_id
        || IS_MAC_BROADCAST(mac)
        || IS_MAC_IPV4_MULTICAST(mac)
        || IS_MAC_IPV6_MULTICAST(mac)) {
        ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        return LUNE_INVALID_ID;
    }

    if (LUNE_ID_NET_IF != sub_type) {
        ERR_SET_ERR(LUNE_ERR_NOT_SUPPORTED);
        return LUNE_INVALID_ID;
    }

    if (NULL == (sub_entry = id_get_entry(sub_type, sub_id))) {
        ERR_SET_ERR(LUNE_ERR_ID_NOT_FOUND);
        return LUNE_INVALID_ID;
    }

    return mac_add_mac(mac, sub_type, sub_entry,
        LUNE_MAC_VID_NONE, LUNE_MAC_VID_NONE);
}

unsigned int lune_add_mac_with_vlan(const lune_mac_addr_t mac,
    lune_id_type_en sub_type,
    unsigned int sub_id,
    unsigned short vid)
{
    void *sub_entry;

    SCHED_CHECK_POINT();

    if (NULL == mac
        || LUNE_INVALID_ID == sub_id
        || IS_MAC_BROADCAST(mac)
        || IS_MAC_IPV4_MULTICAST(mac)
        || IS_MAC_IPV6_MULTICAST(mac)
        || LUNE_MAC_VID_RSVD <= vid
        || LUNE_MAC_VID_NONE == vid) {
        ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        return LUNE_INVALID_ID;
    }

    if (LUNE_ID_NET_IF != sub_type) {
        ERR_SET_ERR(LUNE_ERR_NOT_SUPPORTED);
        return LUNE_INVALID_ID;
    }

    if (NULL == (sub_entry = id_get_entry(sub_type, sub_id))) {
        ERR_SET_ERR(LUNE_ERR_ID_NOT_FOUND);
        return LUNE_INVALID_ID;
    }

    return mac_add_mac(mac, sub_type, sub_entry, vid, LUNE_MAC_VID_NONE);
}

unsigned int lune_add_mac_with_qinq(const lune_mac_addr_t mac,
    lune_id_type_en sub_type,
    unsigned int sub_id,
    unsigned short outer_vid,
    unsigned short inner_vid)
{
    void *sub_entry;

    SCHED_CHECK_POINT();

    if (NULL == mac
        || LUNE_INVALID_ID == sub_id
        || IS_MAC_BROADCAST(mac)
        || IS_MAC_IPV4_MULTICAST(mac)
        || IS_MAC_IPV6_MULTICAST(mac)
        || LUNE_MAC_VID_RSVD <= outer_vid
        || LUNE_MAC_VID_NONE == outer_vid
        || LUNE_MAC_VID_RSVD <= inner_vid
        || LUNE_MAC_VID_NONE == inner_vid) {
        ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        return LUNE_INVALID_ID;
    }

    if (LUNE_ID_NET_IF != sub_type) {
        ERR_SET_ERR(LUNE_ERR_NOT_SUPPORTED);
        return LUNE_INVALID_ID;
    }

    if (NULL == (sub_entry = id_get_entry(sub_type, sub_id))) {
        ERR_SET_ERR(LUNE_ERR_ID_NOT_FOUND);
        return LUNE_INVALID_ID;
    }

    return mac_add_mac(mac, sub_type, sub_entry, outer_vid, inner_vid);
}

int lune_del_mac(unsigned int id)
{
    mac_t *macp;

    SCHED_CHECK_POINT();

    if (LUNE_INVALID_ID == id) {
        return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
    }

    if (NULL == (macp = idtable_find(id, s_mac_idtable))) {
        return ERR_SET_ERR(LUNE_ERR_ID_NOT_FOUND);
    }

    return mac_del_mac(macp);
}

int lune_get_mac(const lune_mac_addr_t mac, lune_id_type_en sub_type,
    unsigned int sub_id, unsigned int *mac_id)
{
    mac_t m, *macp;
    void *sub_entry;

    SCHED_CHECK_POINT();

    if (NULL == mac_id) {
        return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
    }

    if (NULL == mac
        || LUNE_INVALID_ID == sub_id
        || IS_MAC_BROADCAST(mac)
        || IS_MAC_IPV4_MULTICAST(mac)
        || IS_MAC_IPV6_MULTICAST(mac)) {
        *mac_id = LUNE_INVALID_ID;
        return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
    }

    if (LUNE_ID_NET_IF != sub_type) {
        *mac_id = LUNE_INVALID_ID;
        return ERR_SET_ERR(LUNE_ERR_NOT_SUPPORTED);
    }

    if (NULL == (sub_entry = id_get_entry(sub_type, sub_id))) {
        *mac_id = LUNE_INVALID_ID;
        return ERR_SET_ERR(LUNE_ERR_ID_NOT_FOUND);
    }

    LUNE_MAC_CPY(m.mac, mac);
    m.sub_entry = sub_entry;
    m.sub_type = sub_type;
    m.outer_vid = LUNE_MAC_VID_NONE;
    m.inner_vid = LUNE_MAC_VID_NONE;

    if (NULL == (macp = htable_find((void *)&m, s_mac_htable))) {
        *mac_id = LUNE_INVALID_ID;
        /* ERR_SET_ERR() unneeded */
        return -LUNE_ERR_NOT_EXIST;
    }

    *mac_id = macp->id;
    return 0;
}

int lune_get_mac_with_vlan(const lune_mac_addr_t mac, lune_id_type_en sub_type,
    unsigned int sub_id, unsigned short vid, unsigned int *mac_id)
{
    mac_t m, *macp;
    void *sub_entry;

    if (NULL == mac_id) {
        return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
    }

    if (NULL == mac
        || LUNE_INVALID_ID == sub_id
        || IS_MAC_BROADCAST(mac)
        || IS_MAC_IPV4_MULTICAST(mac)
        || IS_MAC_IPV6_MULTICAST(mac)
        || LUNE_MAC_VID_RSVD <= vid
        || LUNE_MAC_VID_NONE == vid) {
        *mac_id = LUNE_INVALID_ID;
        return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
    }

    if (LUNE_ID_NET_IF != sub_type) {
        *mac_id = LUNE_INVALID_ID;
        return ERR_SET_ERR(LUNE_ERR_NOT_SUPPORTED);
    }

    if (NULL == (sub_entry = id_get_entry(sub_type, sub_id))) {
        *mac_id = LUNE_INVALID_ID;
        return ERR_SET_ERR(LUNE_ERR_ID_NOT_FOUND);
    }

    LUNE_MAC_CPY(m.mac, mac);
    m.sub_entry = sub_entry;
    m.sub_type = sub_type;
    m.outer_vid = lune_htons(vid);
    m.inner_vid = LUNE_MAC_VID_NONE;

    if (NULL == (macp = htable_find((void *)&m, s_mac_htable))) {
        *mac_id = LUNE_INVALID_ID;
        /* ERR_SET_ERR() unneeded */
        return -LUNE_ERR_NOT_EXIST;
    }

    *mac_id = macp->id;
    return 0;
}

int lune_get_mac_with_qinq(const lune_mac_addr_t mac,
    lune_id_type_en sub_type,
    unsigned int sub_id,
    unsigned short outer_vid,
    unsigned short inner_vid,
    unsigned int *mac_id)
{
    mac_t m, *macp;
    void *sub_entry;

    if (NULL == mac_id) {
        return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
    }

    if (NULL == mac
        || LUNE_INVALID_ID == sub_id
        || IS_MAC_BROADCAST(mac)
        || IS_MAC_IPV4_MULTICAST(mac)
        || IS_MAC_IPV6_MULTICAST(mac)
        || LUNE_MAC_VID_RSVD <= outer_vid
        || LUNE_MAC_VID_NONE == outer_vid
        || LUNE_MAC_VID_RSVD <= inner_vid
        || LUNE_MAC_VID_NONE == inner_vid) {
        *mac_id = LUNE_INVALID_ID;
        return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
    }

    if (LUNE_ID_NET_IF != sub_type) {
        *mac_id = LUNE_INVALID_ID;
        return ERR_SET_ERR(LUNE_ERR_NOT_SUPPORTED);
    }

    if (NULL == (sub_entry = id_get_entry(sub_type, sub_id))) {
        *mac_id = LUNE_INVALID_ID;
        return ERR_SET_ERR(LUNE_ERR_ID_NOT_FOUND);
    }

    LUNE_MAC_CPY(m.mac, mac);
    m.sub_entry = sub_entry;
    m.sub_type = sub_type;
    m.outer_vid = lune_htons(outer_vid);
    m.inner_vid = lune_htons(inner_vid);

    if (NULL == (macp = htable_find((void *)&m, s_mac_htable))) {
        *mac_id = LUNE_INVALID_ID;
        /* ERR_SET_ERR() unneeded */
        return -LUNE_ERR_NOT_EXIST;
    }

    *mac_id = macp->id;
    return 0;
}

/*
    enabling mac is mainly used for inserting mac to hash table.
    vlan, if any, must be set before mac being enabled
*/
int lune_enable_mac(unsigned int id)
{
    mac_t *macp;

    if (LUNE_INVALID_ID == id) {
        return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
    }

    if (NULL == (macp = mac_get_mac(id))) {
        return ERR_SET_ERR(LUNE_ERR_ID_NOT_FOUND);
    }

    if (MAC_IS_ACTIVE(macp)) {
        return ERR_SET_ERR(LUNE_ERR_MAC_ACTIVE);
    }

    MAC_SET_ACTIVE(macp);

    return 0;
}

int lune_disable_mac(unsigned int id)
{
    mac_t *macp;

    if (LUNE_INVALID_ID == id) {
        return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
    }

    if (NULL == (macp = mac_get_mac(id))) {
        return ERR_SET_ERR(LUNE_ERR_ID_NOT_FOUND);
    }

    if (!MAC_IS_ACTIVE(macp)) {
        return ERR_SET_ERR(LUNE_ERR_MAC_INACTIVE);
    }

    /*
        if LUNE_SOCKET_MAC socket has been created, it must be closed before being disabled
    */
    if (MAC_IS_SOCKET(macp)) {
        return ERR_SET_ERR(LUNE_ERR_NOT_CLOSED);
    }

    MAC_SET_INACTIVE(macp);

    return 0;
}

int lune_str_to_mac(const char *str, lune_mac_addr_t mac)
{
    unsigned int i;

    if (NULL == mac || NULL == str) {
        return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
    }

    for (i = 0; i < LUNE_MAC_ADDR_LEN - 1; i++) {
        if (!LUNE_IS_HEX_CHAR(str[i * 3])
            || !LUNE_IS_HEX_CHAR(str[i * 3 + 1])
            || str[i * 3 + 2] != ':') {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }
        mac[i] = (LUNE_CHAR_TO_HEX(str[i * 3]) << 4) | (LUNE_CHAR_TO_HEX(str[i * 3 + 1]));
    }

    if (!LUNE_IS_HEX_CHAR(str[i * 3])
        || !LUNE_IS_HEX_CHAR(str[i * 3 + 1])) {
        return -1;
    }

    mac[i] = (LUNE_CHAR_TO_HEX(str[i * 3]) << 4) | (LUNE_CHAR_TO_HEX(str[i * 3 + 1]));

    return 0;
}

char *lune_mac_to_str(const lune_mac_addr_t mac, char *buf, int buf_size)
{
    unsigned int i;

    if (NULL == mac || NULL == buf || buf_size < LUNE_MAC_ADDR_STR_LEN) {
        ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        return NULL;
    }

    for (i = 0; i < LUNE_MAC_ADDR_LEN; i++) {
        buf[i * 3] = LUNE_HEX_TO_CHAR((mac[i] & 0xf0) >> 4);
        buf[i * 3 + 1] = LUNE_HEX_TO_CHAR(mac[i] & 0x0f);
        buf[i * 3 + 2] = ':';
    }
    buf[i * 3 - 1] = '\0';

    return buf;
}

int lune_get_mac_opt(unsigned int id,
    lune_mac_opt_en opt, void *opt_val, unsigned int opt_len)
{
    mac_t *macp;

    if (LUNE_INVALID_ID == id || NULL == opt_val) {
        return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
    }

    if (NULL == (macp = mac_get_mac(id))) {
        return ERR_SET_ERR(LUNE_ERR_ID_NOT_FOUND);
    }

    switch (opt) {
    case LUNE_MAC_OPT_GET_MTU:
        if (sizeof(unsigned short) != opt_len) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }
        *(unsigned short *)opt_val = macp->mtu;
        break;
    case LUNE_MAC_OPT_GET_STATS:
        if (sizeof(lune_mac_stats_t) != opt_len) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }
        memcpy(opt_val, &macp->stats, sizeof(lune_mac_stats_t));
        break;
    case LUNE_MAC_OPT_GET_INFO:
        if (sizeof(lune_mac_info_t) != opt_len) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }
        LUNE_MAC_CPY(((lune_mac_info_t *)opt_val)->mac, macp->mac);
        ((lune_mac_info_t *)opt_val)->outer_vid = lune_ntohs(macp->outer_vid);
        ((lune_mac_info_t *)opt_val)->inner_vid = lune_ntohs(macp->inner_vid);
        break;
    case LUNE_MAC_OPT_GET_SUB_INFO:
        if (sizeof(lune_mac_sub_info_t) != opt_len) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }
        ((lune_mac_sub_info_t *)opt_val)->id = sub_entry_get_id(macp->sub_entry, macp->sub_type);
        ((lune_mac_sub_info_t *)opt_val)->type = macp->sub_type;
        break;
    default:
        return ERR_SET_ERR(LUNE_ERR_OPT_NOT_FOUND);
    }

    return 0;
}

unsigned short mac_get_max_hdr_len(mac_t *macp)
{
    return LUNE_ETH_HDR_LEN + LUNE_QINQ_FIELD_LEN
        + pbuf_get_max_hdr_len(macp->sub_type, macp->sub_entry);
}

int lune_set_mac_opt(unsigned int id,
    lune_mac_opt_en opt, const void *opt_val, unsigned int opt_len)
{
    mac_t *macp;

    if (LUNE_INVALID_ID == id || NULL == opt_val) {
        return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
    }

    if (NULL == (macp = mac_get_mac(id))) {
        return ERR_SET_ERR(LUNE_ERR_ID_NOT_FOUND);
    }

    switch (opt) {
    case LUNE_MAC_OPT_SET_MTU:
    {
        unsigned short mtu;

        if (sizeof(unsigned short) != opt_len) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        mtu = *(const unsigned short *)opt_val;
        if (LUNE_NET_IF_MIN_MTU > mtu
            || LUNE_NET_IF_MAX_MTU < mtu) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_MTU);
        }

        if (LUNE_ID_NET_IF == macp->sub_type
            && mtu > NET_IF_GET_MTU(macp->sub_entry)) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_MTU);
        }

        macp->mtu = mtu;
        break;
    }
    default:
        return ERR_SET_ERR(LUNE_ERR_OPT_NOT_FOUND);
    }

    return 0;
}

static int mac_socket_create(socket_t *sk)
{
    mac_pcb_t *pcb = &sk->pcb.mac;

    pcb->cb.recv = NULL;
    pcb->cb.data = NULL;
    pcb->macp = NULL;

    return 0;
}

static int mac_socket_bind(socket_t *sk, const void *arg, unsigned int arg_len)
{
    mac_t *macp;
    mac_pcb_t *pcb;

    if (arg_len != sizeof(unsigned int)) {
        return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
    }

    pcb = &sk->pcb.mac;
    if (NULL != pcb->macp) {
        return ERR_SET_ERR(LUNE_ERR_ALREADY_BOUND);
    }

    if (NULL == (macp = mac_get_mac(*(const unsigned int *)arg))) {
        return ERR_SET_ERR(LUNE_ERR_ID_NOT_FOUND);
    }

    if (MAC_IS_SOCKET(macp)) {
        return ERR_SET_ERR(LUNE_ERR_ALREADY_BOUND);
    }

    if (!MAC_IS_ACTIVE(macp)) {
        return ERR_SET_ERR(LUNE_ERR_MAC_INACTIVE);
    }

    /*
        it is not necessary to mac_hold(macp) because macp cannot be deleted or disabled until socket is close
    */
    pcb->macp = macp;

    MAC_SET_SOCKET(macp);
    /*
        it is not necessary to socket_hold(sk) because macp->sk exists only within the lifetime of socket
    */
    macp->sk = sk;
    sk->rsvd_hdr_len = mac_get_max_hdr_len(macp);

    return 0;
}

static int mac_socket_sendto(socket_t *sk, const unsigned char *buf, unsigned int len,
    const lune_mac_addr_t dst_addr, unsigned int dst_addr_len,
    void *arg, unsigned int arg_len)
{
    mac_t *macp;
    unsigned char lbuf[PBUF_MAX_RSVD_HDR_LEN + LUNE_NET_IF_MAX_MTU];
    pbuf_t pbuf;

    if (dst_addr_len != sizeof(lune_mac_addr_t)
        || NULL == arg || arg_len != sizeof(lune_mac_sendto_arg_t)) {
        return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
    }

    macp = sk->pcb.mac.macp;
    if (unlikely(NULL == macp)) {
        return ERR_SET_ERR(LUNE_ERR_NOT_BOUND);
    }

    if (LUNE_ID_NET_IF != macp->sub_type) {
        return ERR_SET_ERR(LUNE_ERR_NOT_SUPPORTED);
    }

    if (unlikely(len > macp->mtu)) {
        return ERR_SET_ERR(LUNE_ERR_OVERSIZED_PKT);
    }

    pbuf_init_send_pbuf(&pbuf, lbuf, len, PBUF_MAX_RSVD_HDR_LEN, MAC_IS_DPDK(macp));
    if (likely(len > 0)) {
        memcpy(PBUF_GET_PAYLOAD(&pbuf), buf, len);
    }

    return mac_output(macp,
        dst_addr, lune_htons(*(unsigned short *)arg), &pbuf);
}

static int mac_socket_set_opt(socket_t *sk,
    lune_socket_opt_en opt, const unsigned char *opt_val, unsigned int opt_len)
{
    mac_pcb_t *pcb = &sk->pcb.mac;

    switch (opt) {
    case LUNE_SOCKET_OPT_SET_CALLBACK:
        if (NULL == opt_val
            || opt_len != sizeof(lune_mac_socket_callback_t)
            || NULL == ((const lune_mac_socket_callback_t *)opt_val)->recv) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        pcb->cb.recv = ((const lune_mac_socket_callback_t *)opt_val)->recv;
        pcb->cb.data = ((const lune_mac_socket_callback_t *)opt_val)->data;
        break;
    default:
        return ERR_SET_ERR(LUNE_ERR_OPT_NOT_FOUND);
    }

    return 0;
}

static int mac_socket_close(socket_t *sk)
{
    mac_t *macp;
    mac_pcb_t *pcb = &sk->pcb.mac;

    pcb->cb.recv = NULL;

    macp = pcb->macp;
    if (NULL != macp) {
        MAC_SET_NONSOCK(macp);
        macp->sk = NULL;
        pcb->macp = NULL;
    }

    return 0;
}

static unsigned short mac_socket_get_max_hdr_len(socket_t *sk)
{
    mac_t *macp = sk->pcb.mac.macp;

    lune_assert(LUNE_ID_NET_IF == macp->sub_type);

    return mac_get_max_hdr_len(macp);
}

socket_ops_t g_socket_ops_mac = {
    .create = (socket_create_func_t)mac_socket_create,
    .bind = (socket_bind_func_t)mac_socket_bind,
    .connect = NULL,
    .listen = NULL,
    .send = NULL,
    .send_pkts = NULL,
    .sendto = (socket_sendto_func_t)mac_socket_sendto,
    .get_opt = NULL,
    .set_opt = (socket_set_opt_func_t)mac_socket_set_opt,
    .close = (socket_close_func_t)mac_socket_close,
    .hash = NULL,
    .compare = NULL,
    .get_max_hdr_len = (socket_get_max_hdr_len_func_t)mac_socket_get_max_hdr_len,
};
