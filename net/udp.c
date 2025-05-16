/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2024 Lune Reseau, Inc.
 */

#include "lune/assert.h"
#include "lune/id.h"
#include "lune/ip.h"
#include "lune/list.h"
#include "lune/mac.h"
#include "lune/net.h"

#include "kernel/time.h"
#include "kernel/timer.h"
#include "lib/csum.h"
#include "lib/common.h"
#include "lib/htable.h"
#include "lib/idlist.h"
#include "lib/idtable.h"
#include "net/igmp.h"
#include "net/ip.h"
#include "net/mac.h"
#include "net/pbuf.h"
#include "net/socket.h"
#include "net/udp.h"

#define UDP_PRINT_4TUPLE_STR_LEN    (256)
static __thread char s_4tuple_str[UDP_PRINT_4TUPLE_STR_LEN];

static inline char *udp_print_4tuple(ip_t *ipp, lune_ip_addr_t *dst_addr,
    unsigned short src_port, unsigned short dst_port, char *str, unsigned int len)
{
    char src_ip_str[LUNE_IPV6_MAX_ADDR_STR_LEN], dst_ip_str[LUNE_IPV6_MAX_ADDR_STR_LEN];

    lune_assert(NULL != ipp);
    lune_assert(NULL != str);
    lune_assert(UDP_PRINT_4TUPLE_STR_LEN <= len);

    if (IP_IS_IPV6(ipp)) {
        sprintf(str, "<%s:%d, %s:%d>",
            lune_ipv6_to_str(&ipp->ipv6.ip, src_ip_str, LUNE_IPV6_MAX_ADDR_STR_LEN),
            src_port,
            lune_ipv6_to_str(&dst_addr->ipv6, dst_ip_str, LUNE_IPV6_MAX_ADDR_STR_LEN),
            dst_port);
    } else {
        sprintf(str, "<%s:%d, %s:%d>",
            lune_ipv4_to_str(ipp->ipv4.ip, src_ip_str, LUNE_IPV6_MAX_ADDR_STR_LEN),
            src_port,
            lune_ipv4_to_str(dst_addr->ipv4, dst_ip_str, LUNE_IPV6_MAX_ADDR_STR_LEN),
            dst_port);
    }

    return str;
}

int udp_input_multicast(igmp_group_t *igp, lune_ipv4_hdr_t *ipv4h, pbuf_t *pbuf)
{
    igmp_host_group_t *ihgp;
    lune_udp_hdr_t *n_udph = (lune_udp_hdr_t *)PBUF_GET_PAYLOAD(pbuf), h_udph;
    socket_t *sk;

    /* skip checksum check */
    h_udph.src_port = lune_ntohs(n_udph->src_port);
    h_udph.dst_port = lune_ntohs(n_udph->dst_port);
    h_udph.len = lune_ntohs(n_udph->len);
    h_udph.csum = n_udph->csum;

    (void)pbuf_move_up(pbuf, LUNE_UDP_HDR_LEN);

    igmp_group_for_each_host_group(ihgp, igp) {
        udp_pcb_t *pcb;
        dlist_for_each_node(pcb, &ihgp->udp_socket_list, node) {
            if (likely(NULL != pcb->cb.recvfrom)) {
                lune_socket_addr_t addr;

                addr.addr.is_ipv6 = 0;
                addr.addr.ipv4 = ((lune_ipv4_hdr_t *)ipv4h)->src_addr;
                addr.port = h_udph.src_port;

                sk = lune_container_of(pcb, socket_t, pcb.udp);
                socket_hold(sk);
                SOCKET_PUSH_CB_SK(sk);
                pcb->cb.recvfrom(pcb->cb.data, &addr,
                    (const unsigned char *)PBUF_GET_PAYLOAD(pbuf), PBUF_GET_PAYLOAD_LEN(pbuf));
                SOCKET_POP_CB_SK();
                socket_put(sk);
            }
        }
    }

    return 0;
}

int udp_input_unicast(ip_t *ipp, const void *iph, pbuf_t *pbuf)
{
    socket_t *sk, psd_sk;
    udp_pcb_t *pcb;
    lune_udp_hdr_t *n_udph = (lune_udp_hdr_t *)PBUF_GET_PAYLOAD(pbuf), h_udph;
    lune_ip_addr_t dst_ip;

    /* skip checksum check */
    h_udph.src_port = lune_ntohs(n_udph->src_port);
    h_udph.dst_port = lune_ntohs(n_udph->dst_port);
    h_udph.len = lune_ntohs(n_udph->len);
    h_udph.csum = n_udph->csum;

    psd_sk.type = LUNE_SOCKET_UDP;
    psd_sk.ops = &g_socket_ops_udp;
    psd_sk.pcb.udp.ipp = ipp;
    psd_sk.pcb.udp.port = h_udph.dst_port;
    if (NULL == (sk = socket_find(&psd_sk))) {
        return 0;
    }

    pcb = &sk->pcb.udp;
    if (unlikely(UDP_IS_MULTICAST(pcb))) {
        dst_ip.is_ipv6 = IP_IS_IPV6(ipp);
        if (IP_IS_IPV6(ipp)) {
            dst_ip.ipv6 = ((const lune_ipv6_hdr_t *)iph)->src_addr;
        } else {
            dst_ip.ipv4 = ((const lune_ipv4_hdr_t *)iph)->src_addr;
        }

        lune_log(LUNE_INFO, "unicast packet received for multicast udp socket %s",
            udp_print_4tuple(ipp, &dst_ip, h_udph.dst_port, h_udph.src_port,
                s_4tuple_str, UDP_PRINT_4TUPLE_STR_LEN));
        return 0;
    }

    (void)pbuf_move_up(pbuf, LUNE_UDP_HDR_LEN);

    /* hold it till udp_input_unicast() returns */
    socket_hold(sk);

    if (likely(NULL != pcb->cb.recvfrom)) {
        lune_socket_addr_t addr;
        addr.addr.is_ipv6 = IP_IS_IPV6(ipp);
        if (IP_IS_IPV6(ipp)) {
            addr.addr.ipv6 = ((const lune_ipv6_hdr_t *)iph)->src_addr;
        } else {
            addr.addr.ipv4 = ((const lune_ipv4_hdr_t *)iph)->src_addr;
        }
        addr.port = h_udph.src_port;

        SOCKET_PUSH_CB_SK(sk);
        pcb->cb.recvfrom(pcb->cb.data, &addr,
            (const unsigned char *)PBUF_GET_PAYLOAD(pbuf), PBUF_GET_PAYLOAD_LEN(pbuf));
        SOCKET_POP_CB_SK();
    }

    socket_put(sk);

    return 0;
}

static unsigned short udp_socket_get_max_hdr_len(socket_t *sk)
{
    udp_pcb_t *pcb = &sk->pcb.udp;
    unsigned short lower_entry_hdr_len;

    lune_assert(NULL != pcb->ipp);

    lower_entry_hdr_len = pbuf_get_max_hdr_len(
        IP_IS_IPV6(pcb->ipp) ? LUNE_ID_IPV6 : LUNE_ID_IPV4, pcb->ipp);
    return LUNE_UDP_HDR_LEN + lower_entry_hdr_len;
}

static int udp_socket_create(socket_t *sk)
{
    udp_pcb_t *pcb = &sk->pcb.udp;

    pcb->cb.recvfrom = NULL;
    pcb->cb.data = NULL;
    pcb->ipp = NULL;
    pcb->port = 0;
    pcb->flags = 0;

    return 0;
}

static int udp_socket_bind(socket_t *sk, const void *arg, unsigned int arg_len)
{
    ip_t *ipp;
    udp_pcb_t *pcb;
    int err;

    if (unlikely(arg_len != sizeof(lune_socket_addr_t))) {
        return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
    }

    pcb = &sk->pcb.udp;
    if (unlikely(NULL != pcb->ipp)) {
        return ERR_SET_ERR(LUNE_ERR_ALREADY_BOUND);
    }

    lune_assert(!socket_is_added(sk));

    if (unlikely(NULL == (ipp = ip_get_ip_by_id(*(const unsigned int *)arg)))) {
        return ERR_SET_ERR(LUNE_ERR_ID_NOT_FOUND);
    }

    if (unlikely(IP_IS_SOCKET(ipp))) {
        /* ip already bound to ip socket */
        return ERR_SET_ERR(LUNE_ERR_ALREADY_BOUND);
    }

    pcb->ipp = ipp;
    pcb->port = ((const lune_socket_addr_t *)arg)->port;
    if (unlikely(0 != (err = socket_insert(sk)))) {
        pcb->port = 0;
        pcb->ipp = NULL;
        return err;
    }

    ip_hold(ipp);
    IP_SET_L4_SOCKET(ipp);

    sk->rsvd_hdr_len = udp_socket_get_max_hdr_len(sk);

    return 0;
}

static inline unsigned short udp_calc_csum(lune_udp_hdr_t *udph,
    ip_t *ipp,
    const lune_ip_addr_t *dst_ip,
    unsigned short udp_len)
{
    unsigned int sum;

    sum = csum_partial((unsigned char *)udph, udp_len, 0);

    if (IP_IS_IPV6(ipp)) {
        lune_ipv6_psd_hdr_t ipv6h;
        LUNE_IPV6_CPY(ipv6h.src_addr.addr, ipp->ipv6.ip.addr);
        LUNE_IPV6_CPY(ipv6h.dst_addr.addr, dst_ip->ipv6.addr);
        ipv6h.len = lune_htons(udp_len);
        *(unsigned int *)ipv6h.zeros = 0;
        ipv6h.proto = LUNE_IP_PROTO_UDP;
        sum = csum_partial((unsigned char *)&ipv6h, sizeof(lune_ipv6_psd_hdr_t), sum);
    } else {
        lune_ipv4_psd_hdr_t ipv4h;
        ipv4h.src_addr = lune_htonl(ipp->ipv4.ip);
        ipv4h.dst_addr = lune_htonl(dst_ip->ipv4);
        ipv4h.z = 0;
        ipv4h.proto = LUNE_IP_PROTO_UDP;
        ipv4h.len = lune_htons(udp_len);
        sum = csum_partial((unsigned char *)&ipv4h, sizeof(lune_ipv4_psd_hdr_t), sum);
    }

    return csum_fold(sum);
}

int lune_udp_calc_csum(lune_udp_hdr_t *udph,
    lune_ip_addr_t *src_ip,
    lune_ip_addr_t *dst_ip,
    unsigned short udp_len,
    unsigned short *pcsum)
{
    unsigned int sum;

    if (unlikely(NULL == udph
        || NULL == src_ip
        || NULL == dst_ip
        || LUNE_UDP_HDR_LEN > udp_len
        || NULL == pcsum)) {
        return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
    }

    if (unlikely(src_ip->is_ipv6 != dst_ip->is_ipv6)) {
        return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
    }

    sum = csum_partial((unsigned char *)udph, udp_len, 0);

    if (src_ip->is_ipv6) {
        lune_ipv6_psd_hdr_t ipv6h;
        LUNE_IPV6_CPY(ipv6h.src_addr.addr, src_ip->ipv6.addr);
        LUNE_IPV6_CPY(ipv6h.dst_addr.addr, dst_ip->ipv6.addr);
        ipv6h.len = lune_htons(udp_len);
        *(unsigned int *)ipv6h.zeros = 0;
        ipv6h.proto = LUNE_IP_PROTO_UDP;
        sum = csum_partial((unsigned char *)&ipv6h, sizeof(lune_ipv6_psd_hdr_t), sum);
    } else {
        lune_ipv4_psd_hdr_t ipv4h;
        ipv4h.src_addr = lune_htonl(src_ip->ipv4);
        ipv4h.dst_addr = lune_htonl(dst_ip->ipv4);
        ipv4h.z = 0;
        ipv4h.proto = LUNE_IP_PROTO_UDP;
        ipv4h.len = lune_htons(udp_len);
        sum = csum_partial((unsigned char *)&ipv4h, sizeof(lune_ipv4_psd_hdr_t), sum);
    }

    *pcsum = csum_fold(sum);
    return 0;
}

static inline void udp_build_hdr(lune_udp_hdr_t *udph,
    ip_t *ipp,
    const lune_ip_addr_t *dst_ip,
    unsigned short src_port,
    unsigned short dst_port,
    unsigned int data_len,
    unsigned int hw_csum_flag)
{
    udph->src_port = lune_htons(src_port);
    udph->dst_port = lune_htons(dst_port);
    udph->len = lune_htons(LUNE_UDP_HDR_LEN + data_len);
    udph->csum = 0;
    if (!hw_csum_flag) {
        udph->csum = udp_calc_csum(udph, ipp, dst_ip, LUNE_UDP_HDR_LEN + data_len);
    }
}

static inline int udp_output_frag(udp_pcb_t *pcb,
    const lune_ip_addr_t *dst_ip, unsigned short port, pbuf_t *pbuf)
{
    lune_udp_hdr_t *udph;

    udph = (lune_udp_hdr_t *)pbuf_move_down(pbuf, LUNE_UDP_HDR_LEN);
    pbuf->l4_len = LUNE_UDP_HDR_LEN + PBUF_GET_PAYLOAD_LEN(pbuf);
    PBUF_SET_L4_TYPE_UDP(pbuf);

    udp_build_hdr(udph, pcb->ipp, dst_ip, pcb->port, port, PBUF_GET_PAYLOAD_LEN(pbuf), 0);

    return ip_output(pcb->ipp, dst_ip, LUNE_IP_PROTO_UDP, pbuf);
}

static inline int udp_output_nofrag(udp_pcb_t *pcb,
    const lune_ip_addr_t *dst_ip, unsigned short port, unsigned int hw_csum_flag, pbuf_t *pbuf)
{
    lune_udp_hdr_t *udph;

    udph = (lune_udp_hdr_t *)pbuf_move_down(pbuf, LUNE_UDP_HDR_LEN);
    pbuf->l4_len = LUNE_UDP_HDR_LEN + PBUF_GET_PAYLOAD_LEN(pbuf);
    PBUF_SET_L4_TYPE_UDP(pbuf);

    udp_build_hdr(udph, pcb->ipp, dst_ip, pcb->port, port, PBUF_GET_PAYLOAD_LEN(pbuf), hw_csum_flag);

    return ip_output_nofrag(pcb->ipp, dst_ip, LUNE_IP_PROTO_UDP, pbuf);
}

static int udp_socket_sendto(socket_t *sk, const unsigned char *buf, unsigned int len,
    const void *dst_addr, unsigned int dst_addr_len, const void *arg, unsigned int arg_len)
{
    udp_pcb_t *pcb;
    unsigned char lbuf[PBUF_MAX_RSVD_HDR_LEN + IP_MAX_PAYLOAD_BUF_SIZE];
    pbuf_t pbuf;
    unsigned int hw_csum_flag, ip_payload_len;

    if (unlikely(dst_addr_len != sizeof(lune_socket_addr_t)
        || NULL != arg || arg_len != 0)) {
        return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
    }

    pcb = &sk->pcb.udp;

    if (UDP_IS_MULTICAST(pcb)) {
        if (unlikely(((const lune_socket_addr_t *)dst_addr)->addr.ipv4 != pcb->group_addr)) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }
    }

    if (unlikely(NULL == pcb->ipp)) {
        return ERR_SET_ERR(LUNE_ERR_NOT_BOUND);
    }

    ip_payload_len = len + LUNE_UDP_HDR_LEN;
    if (unlikely(!IP_IS_PAYLOAD_LEN_VALID(pcb->ipp, ip_payload_len))) {
        return ERR_SET_ERR(LUNE_ERR_OVERSIZED_PKT);
    }

    if (!ip_is_pkt_frag(pcb->ipp, ip_payload_len)) {
        hw_csum_flag = IP_IS_HW_TX_UDP_CSUM(pcb->ipp) ? 1 : 0;

        pbuf_init_send_pbuf(&pbuf, lbuf, len, PBUF_MAX_RSVD_HDR_LEN, IP_IS_DPDK(pcb->ipp));
        if (likely(len > 0)) {
            memcpy(PBUF_GET_HDR(&pbuf), buf, len);
        }

        return udp_output_nofrag(pcb,
            &((const lune_socket_addr_t *)dst_addr)->addr,
            ((const lune_socket_addr_t *)dst_addr)->port,
            hw_csum_flag,
            &pbuf);
    }

    /* fragmented packets */

    pbuf_init_send_pbuf(&pbuf, lbuf, len, PBUF_MAX_RSVD_HDR_LEN, 0);
    if (likely(len > 0)) {
        memcpy(PBUF_GET_HDR(&pbuf), buf, len);
    }

    return udp_output_frag(pcb,
        &((const lune_socket_addr_t *)dst_addr)->addr,
        ((const lune_socket_addr_t *)dst_addr)->port,
        &pbuf);
}

static int udp_socket_get_opt(socket_t *sk, lune_socket_opt_en opt, unsigned char *opt_val, unsigned int opt_len)
{
    udp_pcb_t *pcb = &sk->pcb.udp;

    switch (opt) {
    case LUNE_SOCKET_OPT_GET_SRC_IP_ID:
        if (unlikely(NULL == opt_val || opt_len != sizeof(unsigned int))) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        if (NULL == pcb->ipp) {
            return ERR_SET_ERR(LUNE_ERR_NOT_BOUND);
        }

        *(unsigned int *)opt_val = IP_GET_ID(pcb->ipp);
        break;
    default:
        return ERR_SET_ERR(LUNE_ERR_OPT_NOT_FOUND);
    }

    return 0;
}

static int udp_socket_join_host_group(udp_pcb_t *pcb, lune_ipv4_addr_t group_addr)
{
    igmp_group_t *igp;
    igmp_host_group_t *ihgp, ihg;

    if (NULL == (igp = igmp_find_group(group_addr))) {
        return ERR_SET_ERR(LUNE_ERR_NOT_EXIST);
    }

    ihg.ipv4p = pcb->ipp;
    ihg.igp = igp;
    if (NULL == (ihgp = htable_find((void *)&ihg, igp->host_group_htable))) {
        return ERR_SET_ERR(LUNE_ERR_NOT_EXIST);
    }

    pcb->group_addr = group_addr;
    dlist_add_tail(&pcb->node, &ihgp->udp_socket_list);
    return 0;
}

static void udp_socket_leave_host_group(udp_pcb_t *pcb)
{
    dlist_del_init(&pcb->node);
    pcb->group_addr = 0;
}

static int udp_socket_set_opt(socket_t *sk,
    lune_socket_opt_en opt, const unsigned char *opt_val, unsigned int opt_len)
{
    udp_pcb_t *pcb = &sk->pcb.udp;
    int err;

    switch (opt) {
    case LUNE_SOCKET_OPT_SET_CALLBACK:
        if (unlikely(NULL == opt_val
            || opt_len != sizeof(lune_udp_socket_callback_t))) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        pcb->cb.recvfrom = ((const lune_udp_socket_callback_t *)opt_val)->recvfrom;
        pcb->cb.data = ((const lune_udp_socket_callback_t *)opt_val)->data;
        break;
    case LUNE_SOCKET_OPT_ADD_MEMBERSHIP:
        if (unlikely(NULL == opt_val
            || opt_len != sizeof(lune_ipv4_addr_t))) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        if (unlikely(NULL == pcb->ipp)) {
            return ERR_SET_ERR(LUNE_ERR_NOT_BOUND);
        }

        if (IP_IS_IPV6(pcb->ipp)) {
            /* TODO: MLD for ipv6 */
            return ERR_SET_ERR(LUNE_ERR_NOT_SUPPORTED);
        }

        if (unlikely(UDP_IS_MULTICAST(pcb))) {
            return ERR_SET_ERR(LUNE_ERR_ALREADY_SET);
        }

        if (unlikely(!IPV4_IS_MULTICAST_IP(*(const lune_ipv4_addr_t *)opt_val))) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        if (0 != (err = udp_socket_join_host_group(pcb, *(const lune_ipv4_addr_t *)opt_val))) {
            return err;
        }

        UDP_SET_MULTICAST(pcb);
        break;
    case LUNE_SOCKET_OPT_DROP_MEMBERSHIP:
        if (unlikely(NULL != opt_val || 0 != opt_len)) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        if (unlikely(NULL == pcb->ipp)) {
            return ERR_SET_ERR(LUNE_ERR_NOT_BOUND);
        }

        if (IP_IS_IPV6(pcb->ipp)) {
            /* TODO: MLD for ipv6 */
            return ERR_SET_ERR(LUNE_ERR_NOT_SUPPORTED);
        }

        if (unlikely(!UDP_IS_MULTICAST(pcb))) {
            return ERR_SET_ERR(LUNE_ERR_NOT_SET);
        }

        udp_socket_leave_host_group(pcb);
        UDP_CLEAR_MULTICAST(pcb);
        break;
    default:
        return ERR_SET_ERR(LUNE_ERR_OPT_NOT_FOUND);
    }

    return 0;
}

static int udp_socket_close(socket_t *sk)
{
    udp_pcb_t *pcb = &sk->pcb.udp;

    pcb->cb.recvfrom = NULL;

    if (UDP_IS_MULTICAST(pcb)) {
        udp_socket_leave_host_group(pcb);
        UDP_CLEAR_MULTICAST(pcb);
    }

    if (NULL != pcb->ipp) {
        lune_assert(!socket_remove(sk));
        ip_put(pcb->ipp);
        pcb->ipp = NULL;
    } else {
        lune_assert(!socket_is_added(sk));
    }

    return 0;
}

static unsigned int udp_socket_hash(socket_pcb_un *pcb)
{
    return IP_IS_IPV6(pcb->udp.ipp)
        ? (((lune_ntohl(pcb->udp.ipp->ipv6.ip.addr[3]) << 16) + pcb->udp.port) & SOCKET_HTABLE_MASK)
        : (((pcb->udp.ipp->ipv4.ip << 16) + pcb->udp.port) & SOCKET_HTABLE_MASK);
}

static int udp_socket_compare(socket_pcb_un *pcb1, socket_pcb_un *pcb2)
{
    return (pcb1->udp.ipp == pcb2->udp.ipp && pcb1->udp.port == pcb2->udp.port) ? 0 : 1;
}

socket_ops_t g_socket_ops_udp = {
    .create = (socket_create_func_t)udp_socket_create,
    .bind = (socket_bind_func_t)udp_socket_bind,
    .connect = NULL,
    .listen = NULL,
    .send = NULL,
    .send_pkts = NULL,
    .sendto = (socket_sendto_func_t)udp_socket_sendto,
    .get_opt = (socket_get_opt_func_t)udp_socket_get_opt,
    .set_opt = (socket_set_opt_func_t)udp_socket_set_opt,
    .close = (socket_close_func_t)udp_socket_close,
    .hash = (socket_hash_func_t)udp_socket_hash,
    .compare = (socket_compare_func_t)udp_socket_compare,
    .get_max_hdr_len = (socket_get_max_hdr_len_func_t)udp_socket_get_max_hdr_len,
};

int udp_local_init(void)
{
    return 0;
}

void udp_local_fini(void)
{
}
