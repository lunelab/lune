/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2024 Lune Reseau, Inc.
 */

#include "lune/assert.h"
#include "lune/conv.h"
#include "lune/id.h"
#include "lune/ip.h"
#include "lune/list.h"
#include "lune/log.h"
#include "lune/mac.h"
#include "lune/net.h"
#include "lune/time.h"

#include "kernel/time.h"
#include "kernel/timer.h"
#include "lib/common.h"
#include "lib/csum.h"
#include "lib/htable.h"
#include "lib/idlist.h"
#include "lib/idtable.h"
#include "net/arp.h"
#include "net/ip.h"
#include "net/mac.h"
#include "net/pbuf.h"
#include "net/socket.h"
#include "net/tcp.h"

#define IP_HTABLE_SIZE_IN_BIT   (20)
#define IP_HTABLE_SIZE          (1 << (IP_HTABLE_SIZE_IN_BIT))
#define IP_HTABLE_MASK          (IP_HTABLE_SIZE - 1)

/*
    NOTICE:

    Ip address over interface (not over socket) is unique per core
    as it is stored in thread-local global hash table. Therefore,
    adding duplicate ip will fail if:
    1. on same interface as first ip
    2. on interface different from the one where first ip resides if
       both interfaces run on same core
*/

__thread void *g_ip_idlist = NULL;

__thread void *g_ip_idtable = NULL;

__thread void *g_ip_htable = NULL;

ip_t *ip_get_ip_by_addr(void *addr,
    unsigned int is_ipv6, lune_id_type_en sub_type, void *sub_entry, void *ifp)
{
    ip_t ip;

    ip.flags = 0;
    if (is_ipv6) {
        IP_SET_IPV6(&ip);
        LUNE_IPV6_CPY(ip.ipv6.ip.addr, (unsigned int *)addr);
    } else {
        /* IP_SET_IPV4() included in flags initialization */
        ip.ipv4.ip = *(lune_ipv4_addr_t *)addr;
    }

    ip.sub_type = sub_type;
    ip.sub_entry = sub_entry;
    ip.ifp = ifp;

    return htable_find((void *)&ip, g_ip_htable);
}

ip_t *ip_get_ip_by_id(unsigned int id)
{
    lune_assert(LUNE_INVALID_ID != id);

    return idtable_find(id, g_ip_idtable);
}

void ip_set_net_if_hw_csum_flags(ip_t *ipp)
{
    if (NULL == ipp->ifp) {
        return;
    }

    if (NET_IF_IS_HW_RX_IPV4_CSUM(ipp->ifp)) {
        IP_SET_HW_RX_IP_CSUM(ipp);
    }
    if (NET_IF_IS_HW_RX_TCP_CSUM(ipp->ifp)) {
        IP_SET_HW_RX_TCP_CSUM(ipp);
    }
    if (NET_IF_IS_HW_RX_UDP_CSUM(ipp->ifp)) {
        IP_SET_HW_RX_UDP_CSUM(ipp);
    }

    if (NET_IF_IS_HW_TX_IPV4_CSUM(ipp->ifp)) {
        IP_SET_HW_TX_IP_CSUM(ipp);
    }
    if (NET_IF_IS_HW_TX_TCP_CSUM(ipp->ifp)) {
        IP_SET_HW_TX_TCP_CSUM(ipp);
    }
    if (NET_IF_IS_HW_TX_UDP_CSUM(ipp->ifp)) {
        IP_SET_HW_TX_UDP_CSUM(ipp);
    }
}

unsigned short ip_get_mtu(ip_t *ipp)
{
    lune_assert(LUNE_ID_MAC == ipp->sub_type);
    return mac_get_mtu((mac_t *)ipp->sub_entry);
}

static void ip_idtable_free(ip_t *ipp)
{
    lune_assert(!idlist_del_id(ipp->id, g_ip_idlist));
    ip_put(ipp);
}

static void ip_htable_free(ip_t *ipp)
{
    IP_SET_DELETED(ipp);

    sub_entry_put(ipp->sub_entry, ipp->sub_type);
    ipp->sub_entry = NULL;

    ip_put(ipp);
}

static int ip_htable_hash(ip_t *ipp)
{
    return (int)(IP_IS_IPV6(ipp) ? (lune_ntohl(ipp->ipv6.ip.addr[3]) & IP_HTABLE_MASK)
        : (ipp->ipv4.ip & IP_HTABLE_MASK));
}

static int ip_htable_compare(ip_t *ipp1, ip_t *ipp2)
{
    return (!(IP_IS_IPV6(ipp1) == IP_IS_IPV6(ipp2)
        && (IP_IS_IPV6(ipp1)
        ? (!LUNE_IPV6_CMP(ipp1->ipv6.ip.addr, ipp2->ipv6.ip.addr))
        : ipp1->ipv4.ip == ipp2->ipv4.ip)
        && ipp1->sub_type == ipp2->sub_type
        /* ip must be unique for mac-based network on an interface */
        && ipp1->ifp == ipp2->ifp
        && (ipp1->sub_type == LUNE_ID_MAC
        || ipp1->sub_entry == ipp2->sub_entry)));
}

int lune_get_ip_opt(unsigned int id,
    lune_ip_opt_en opt, void *opt_val, unsigned int opt_len)
{
    ip_t *ipp;

    if (LUNE_INVALID_ID == id || NULL == opt_val) {
        return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
    }

    if (NULL == (ipp = ip_get_ip_by_id(id))) {
        return ERR_SET_ERR(LUNE_ERR_ID_NOT_FOUND);
    }

    switch (opt) {
    case LUNE_IP_OPT_GET_STATS:
        if (sizeof(lune_ip_stats_t) != opt_len) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }
        memcpy(opt_val, &ipp->stats, sizeof(lune_ip_stats_t));
        break;
    case LUNE_IP_OPT_GET_SUB_INFO:
        if (sizeof(lune_ip_sub_info_t) != opt_len) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }
        ((lune_ip_sub_info_t *)opt_val)->id = sub_entry_get_id(ipp->sub_entry, ipp->sub_type);
        ((lune_ip_sub_info_t *)opt_val)->type = ipp->sub_type;
        break;
    case LUNE_IP_OPT_GET_ADDR:
        if (sizeof(lune_ip_addr_t) != opt_len) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        ((lune_ip_addr_t *)opt_val)->is_ipv6 = IP_IS_IPV6(ipp);
        if (IP_IS_IPV6(ipp)) {
            LUNE_IPV6_CPY(((lune_ip_addr_t *)opt_val)->ipv6.addr, &ipp->ipv6.ip);
        } else {
            ((lune_ip_addr_t *)opt_val)->ipv4 = ipp->ipv4.ip;
        }

        break;
    case LUNE_IP_OPT_GET_SOCKET_ID:
        if (sizeof(unsigned int) != opt_len) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        if (NULL == ipp->sk) {
            return ERR_SET_ERR(LUNE_ERR_NOT_BOUND);
        }

        *(unsigned int *)opt_val = SOCKET_GET_ID(ipp->sk);
        break;
    default:
        return ERR_SET_ERR(LUNE_ERR_OPT_NOT_FOUND);
    }

    return 0;
}

int lune_set_ip_opt(unsigned int id,
    lune_ip_opt_en opt, const void *opt_val, unsigned int opt_len)
{
    ip_t *ipp;

    if (LUNE_INVALID_ID == id) {
        return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
    }

    if (NULL == (ipp = ip_get_ip_by_id(id))) {
        return ERR_SET_ERR(LUNE_ERR_ID_NOT_FOUND);
    }

    switch (opt) {
    case LUNE_IP_OPT_ADD_MEMBERSHIP:
        if (unlikely(IP_IS_IPV6(ipp))) {
            return ERR_SET_ERR(LUNE_ERR_NOT_SUPPORTED);
        }

        if (unlikely(NULL == opt_val
            || opt_len != sizeof(lune_ipv4_join_group_arg_t))) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        return ipv4_join_group(ipp, (const lune_ipv4_join_group_arg_t *)opt_val);
    case LUNE_IP_OPT_DROP_MEMBERSHIP:
        if (unlikely(IP_IS_IPV6(ipp))) {
            return ERR_SET_ERR(LUNE_ERR_NOT_SUPPORTED);
        }

        if (unlikely(NULL == opt_val
            || opt_len != sizeof(lune_ipv4_addr_t))) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        return ipv4_leave_group(ipp, *(const lune_ipv4_addr_t *)opt_val);
    case LUNE_IP_OPT_DISABLE_ARP:
        if (unlikely(IP_IS_IPV6(ipp))) {
            return ERR_SET_ERR(LUNE_ERR_NOT_SUPPORTED);
        }

        if (unlikely(NULL != opt_val || 0 != opt_len)) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        if (unlikely(IP_IS_ARP_DISABLED(ipp))) {
            return ERR_SET_ERR(LUNE_ERR_ALREADY_SET);
        }

        IP_SET_ARP_DISABLED(ipp);
        break;
    case LUNE_IP_OPT_ENABLE_ARP:
        if (unlikely(IP_IS_IPV6(ipp))) {
            return ERR_SET_ERR(LUNE_ERR_NOT_SUPPORTED);
        }

        if (unlikely(NULL != opt_val || 0 != opt_len)) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        if (unlikely(!IP_IS_ARP_DISABLED(ipp))) {
            return ERR_SET_ERR(LUNE_ERR_ALREADY_SET);
        }

        IP_SET_ARP_ENABLED(ipp);
        break;
    default:
        return ERR_SET_ERR(LUNE_ERR_OPT_NOT_FOUND);
    }

    return 0;
}

static int ip_socket_create(socket_t *sk)
{
    ip_pcb_t *pcb = &sk->pcb.ip;

    pcb->cb.recvfrom = NULL;
    pcb->cb.data = NULL;
    pcb->ipp = NULL;

    return 0;
}

static int ip_socket_bind(socket_t *sk, const void *arg, unsigned int arg_len)
{
    ip_t *ipp;
    ip_pcb_t *pcb;

    if (arg_len != sizeof(unsigned int)) {
        return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
    }

    pcb = &sk->pcb.ip;
    if (NULL != pcb->ipp) {
        return ERR_SET_ERR(LUNE_ERR_ALREADY_BOUND);
    }

    if (NULL == (ipp = ip_get_ip_by_id(*(const unsigned int *)arg))) {
        return ERR_SET_ERR(LUNE_ERR_ID_NOT_FOUND);
    }

    if (IP_IS_SOCKET(ipp) || IP_L4_SOCKET_EXIST(ipp)) {
        return ERR_SET_ERR(LUNE_ERR_ALREADY_BOUND);
    }

    /*
        it is not necessary to ip_hold(ipp) because ipp cannot be deleted until socket is close
    */
    pcb->ipp = ipp;

    IP_SET_SOCKET(ipp);
    /*
        it is not necessary to socket_hold(sk) because ipp->sk exists only within the lifetime of socket
    */
    ipp->sk = sk;
    if (IP_IS_IPV6(ipp)) {
        sk->rsvd_hdr_len = ipv6_get_max_hdr_len(ipp);
    } else {
        sk->rsvd_hdr_len = ipv4_get_max_hdr_len(ipp);
    }

    return 0;
}

static int ip_socket_sendto(socket_t *sk, const unsigned char *buf, unsigned int len,
    const lune_ip_addr_t *dst_addr, unsigned int dst_addr_len,
    const lune_ip_sendto_arg_t *arg, unsigned int arg_len)
{
    ip_pcb_t *pcb;
    unsigned char lbuf[PBUF_MAX_RSVD_HDR_LEN + IP_MAX_PAYLOAD_BUF_SIZE];
    pbuf_t pbuf;

    if (unlikely(dst_addr_len != sizeof(lune_ip_addr_t)
        || NULL == arg || arg_len != sizeof(lune_ip_sendto_arg_t))) {
        return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
    }

    pcb = &sk->pcb.ip;

    if (unlikely(NULL == pcb->ipp)) {
        return ERR_SET_ERR(LUNE_ERR_NOT_BOUND);
    }

    if ((IP_IS_IPV6(pcb->ipp) && !dst_addr->is_ipv6)
        || (!IP_IS_IPV6(pcb->ipp) && dst_addr->is_ipv6)) {
        return ERR_SET_ERR(LUNE_ERR_IP_TYPE_MISMATCH);
    }

    if (unlikely(!IP_IS_PAYLOAD_LEN_VALID(pcb->ipp, len))) {
        return ERR_SET_ERR(LUNE_ERR_OVERSIZED_PKT);
    }

    if (!ip_is_pkt_frag(pcb->ipp, len)) {
        pbuf_init_send_pbuf(&pbuf, lbuf, len, PBUF_MAX_RSVD_HDR_LEN, IP_IS_DPDK(pcb->ipp));
        if (likely(len > 0)) {
            memcpy(PBUF_GET_HDR(&pbuf), buf, len);
        }

        return ip_output_nofrag(pcb->ipp, dst_addr, arg->proto, &pbuf);
    }

    /* fragmented packets */

    pbuf_init_send_pbuf(&pbuf, lbuf, len, PBUF_MAX_RSVD_HDR_LEN, 0);
    if (likely(len > 0)) {
        memcpy(PBUF_GET_HDR(&pbuf), buf, len);
    }

    return ip_output(pcb->ipp, dst_addr, arg->proto, &pbuf);
}

static int ip_socket_get_opt(socket_t *sk, lune_socket_opt_en opt, unsigned char *opt_val, unsigned int opt_len)
{
    ip_pcb_t *pcb = &sk->pcb.ip;

    switch (opt) {
    case LUNE_SOCKET_OPT_GET_SRC_IP_ID:
        if (unlikely(NULL == opt_val || opt_len != sizeof(unsigned int))) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        if (NULL == pcb->ipp) {
            return ERR_SET_ERR(LUNE_ERR_NOT_BOUND);
        }

        *(unsigned int *)opt_val = pcb->ipp->id;
        break;
    default:
        return ERR_SET_ERR(LUNE_ERR_OPT_NOT_FOUND);
    }

    return 0;
}

static int ip_socket_set_opt(socket_t *sk,
    lune_socket_opt_en opt, const unsigned char *opt_val, unsigned int opt_len)
{
    ip_pcb_t *pcb = &sk->pcb.ip;

    switch (opt) {
    case LUNE_SOCKET_OPT_SET_CALLBACK:
        if (NULL == opt_val
            || opt_len != sizeof(lune_ip_socket_callback_t)) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        pcb->cb.recvfrom = ((const lune_ip_socket_callback_t *)opt_val)->recvfrom;
        pcb->cb.data = ((const lune_ip_socket_callback_t *)opt_val)->data;
        break;
    default:
        return ERR_SET_ERR(LUNE_ERR_OPT_NOT_FOUND);
    }

    return 0;
}

static int ip_socket_close(socket_t *sk)
{
    ip_t *ipp;
    ip_pcb_t *pcb = &sk->pcb.ip;

    pcb->cb.recvfrom = NULL;

    ipp = pcb->ipp;
    if (NULL != ipp) {
        IP_SET_NON_SOCK(ipp);
        ipp->sk = NULL;
        pcb->ipp = NULL;
    }

    return 0;
}

static unsigned short ip_socket_get_max_hdr_len(socket_t *sk)
{
    ip_t *ipp = sk->pcb.ip.ipp;

    lune_assert(LUNE_ID_MAC == ipp->sub_type);

    if (IP_IS_IPV6(ipp)) {
        return ipv6_get_max_hdr_len(ipp);
    } else {
        return ipv4_get_max_hdr_len(ipp);
    }
}

socket_ops_t g_socket_ops_ip = {
    .create = (socket_create_func_t)ip_socket_create,
    .bind = (socket_bind_func_t)ip_socket_bind,
    .connect = NULL,
    .listen = NULL,
    .send = NULL,
    .send_pkts = NULL,
    .sendto = (socket_sendto_func_t)ip_socket_sendto,
    .get_opt = (socket_get_opt_func_t)ip_socket_get_opt,
    .set_opt = (socket_set_opt_func_t)ip_socket_set_opt,
    .close = (socket_close_func_t)ip_socket_close,
    .hash = NULL,
    .compare = NULL,
    .get_max_hdr_len = (socket_get_max_hdr_len_func_t)ip_socket_get_max_hdr_len,
};

int ip_local_init(void)
{
    int err;

    if (NULL == (g_ip_idlist = idlist_create_list("ip id list"))) {
        goto ERR_1;
    }

    if (NULL == (g_ip_idtable = idtable_create_table("ip id table", 
        (idtable_free_func_t)ip_idtable_free, 
        IDTABLE_MAX_TABLE_SIZE))) {
        goto ERR_2;
    }

    if (NULL == (g_ip_htable = htable_create_table("ip hash table",
        (htable_hash_func_t)ip_htable_hash,
        (htable_compare_func_t)ip_htable_compare,
        (htable_free_func_t)ip_htable_free,
        offsetof(ip_t, node),
        IP_HTABLE_SIZE,
        0))) {
        goto ERR_3;
    }

    if (0 != (err = ipv4_local_init())) {
        goto ERR_4;
    }

    if (0 != (err = ipv6_local_init())) {
        goto ERR_5;
    }

    return 0;

ERR_5:
    ipv4_local_fini();

ERR_4:
    lune_assert(!htable_delete_table(g_ip_htable));
    g_ip_htable = NULL;

ERR_3:
    lune_assert(!idtable_delete_table(g_ip_idtable));
    g_ip_idtable = NULL;

ERR_2:
    lune_assert(!idlist_delete_list(g_ip_idlist));
    g_ip_idlist = NULL;

ERR_1:
    return ERR_GET_LAST_ERR();
}

void ip_local_fini(void)
{
    ipv6_local_fini();

    ipv4_local_fini();

    lune_assert(!htable_delete_table(g_ip_htable));
    g_ip_htable = NULL;

    lune_assert(!idtable_delete_table(g_ip_idtable));
    g_ip_idtable = NULL;

    lune_assert(!idlist_delete_list(g_ip_idlist));
    g_ip_idlist = NULL;
}
