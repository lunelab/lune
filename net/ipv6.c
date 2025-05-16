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
#include "lune/mem.h"
#include "lune/net.h"
#include "lune/time.h"

#include "kernel/sched.h"
#include "kernel/time.h"
#include "kernel/timer.h"
#include "lib/common.h"
#include "lib/csum.h"
#include "lib/htable.h"
#include "lib/idlist.h"
#include "lib/idtable.h"
#include "net/id.h"
#include "net/ip.h"
#include "net/mac.h"
#include "net/nb.h"
#include "net/pbuf.h"
#include "net/tcp.h"

#define IPV6_IS_MULTICAST_IP(ip)                (0xff == ((const lune_ipv6_addr_t *)(ip))->octet[0])
#define IPV6_IS_SOLICIT_NODE_MULTICAST_IP(ip)   \
    (*(unsigned long long *)(&g_ipv6_solicit_node_multicast_ip) == *(const unsigned long long *)ip  \
    && g_ipv6_solicit_node_multicast_ip.addr[2] == ((const lune_ipv6_addr_t *)(ip))->addr[2]        \
    && g_ipv6_solicit_node_multicast_ip.octet[12] == (((const lune_ipv6_addr_t *)(ip))->octet[12]))

#define IPV6_MAX_HDR_LEN                        (60)
#define IPV6_DEFAULT_TRF_CLASS                  (0)
#define IPV6_DEFAULT_FLOW_LABEL                 (0)
#define IPV6_DEFAULT_HOP_LIMIT                  (255)
#define IPV6_DEFAULT_MTU                        (1280)

#define IPV6_FRAG_HTABLE_SIZE_IN_BIT            (18)
#define IPV6_FRAG_HTABLE_SIZE                   (1 << (IPV6_FRAG_HTABLE_SIZE_IN_BIT))
#define IPV6_FRAG_HTABLE_MASK                   (IPV6_FRAG_HTABLE_SIZE - 1)

#define IPV6_DEFRAG_TIMEOUT                     (LUNE_TIME_SECOND * 60)

#define IPV6_IS_FRAG(ipv6h)                     \
    (LUNE_IP_PROTO_IPV6_FRAG == ((const lune_ipv6_hdr_t *)(ipv6h))->next_hdr)
#define IPV6_IS_LAST_FRAG(ipv6fh)               \
    (((((const lune_ipv6_frag_hdr_t *)(ipv6fh))->offset) & LUNE_IPV6_FRAG_MF) == 0)
/* ipv6h MUST be last fragment */
#define IPV6_GET_FRAG_TOTAL_LEN(ipv6h, ipv6fh)  \
    (((((const lune_ipv6_frag_hdr_t *)(ipv6fh))->offset) & LUNE_IPV6_FRAG_OFFSET)   \
    + ((const lune_ipv6_hdr_t *)(ipv6h))->payload_len - LUNE_IPV6_FRAG_HDR_LEN)

#define IPV6_DEFRAG_COMPLETE                    (0)
#define IPV6_DEFRAG_INCOMPLETE                  (1)

#pragma pack(1)
typedef struct _ipv6_frag {
    dlist_node_t node;
    unsigned short offset;
    unsigned short len;
    unsigned int rsvd;      /* reserved for memory alignment */
    unsigned char payload[0];
} ipv6_frag_t;
#pragma pack()

typedef struct _ipv6_defrag {
    dlist_head_t head;
    dlist_node_t node;
    lune_timer_t tmr;
    lune_ipv6_addr_t src_addr;
    lune_ipv6_addr_t dst_addr;
    unsigned short id;
    unsigned short total_len;
    unsigned short cur_len;
    unsigned char next_hdr;
} ipv6_defrag_t;

/* ff02::1:ff00:0/104 Solicited-Node multicast address prefix */
lune_ipv6_addr_t g_ipv6_solicit_node_multicast_ip = {
    .octet = {
        0xff, 0x02, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x01,
        0xff, 0x00, 0x00, 0x00,
    }
};

static __thread void *s_ipv6_frag_htable = NULL;

static inline ipv6_frag_t *ipv6_create_frag(unsigned char *buf, unsigned short len, unsigned short offset)
{
    ipv6_frag_t *frag;

    lune_assert(NULL != buf);
    lune_assert(offset <= LUNE_IPV6_FRAG_OFFSET);
    lune_assert(len > 0);

    if (NULL == (frag = lune_malloc(sizeof(ipv6_frag_t) + len))) {
        return NULL;
    }

    dlist_init_node(&frag->node);
    frag->offset = offset;
    frag->len = len;
    frag->rsvd = 0;
    memcpy(frag->payload, buf, len);

    return frag;
}

static inline void ipv6_delete_frag(ipv6_frag_t *frag)
{
    lune_free(frag);
}

static void ipv6_defrag_timeout(ipv6_defrag_t *defrag);

static inline ipv6_defrag_t *ipv6_create_defrag(lune_ipv6_addr_t *src_addr,
    lune_ipv6_addr_t *dst_addr, unsigned short id, unsigned char next_hdr)
{
    ipv6_defrag_t *defrag;

    if (NULL == (defrag = lune_malloc(sizeof(ipv6_defrag_t)))) {
        return NULL;
    }

    dlist_init_head(&defrag->head);
    dlist_init_node(&defrag->node);
    timer_init_timer(&defrag->tmr,
        LUNE_TIMER_ONCE, LUNE_TIMER_RES_HIGH, (lune_timer_func_t)ipv6_defrag_timeout, defrag);
    LUNE_IPV6_CPY(&defrag->src_addr, src_addr);
    LUNE_IPV6_CPY(&defrag->dst_addr, dst_addr);
    defrag->id = id;
    defrag->cur_len = 0;
    defrag->total_len = 0;
    defrag->next_hdr = next_hdr;

    timer_add_timer(&defrag->tmr, IPV6_DEFRAG_TIMEOUT);

    return defrag;
}

static inline void ipv6_delete_defrag(ipv6_defrag_t *defrag)
{
    ipv6_frag_t *frag, *frag2;

    lune_assert(NULL != defrag);

    dlist_for_each_node_safe(frag, frag2, &defrag->head, node) {
        dlist_del(&frag->node);
        ipv6_delete_frag(frag);
    }

    (void)timer_del_timer(&defrag->tmr);

    lune_free(defrag);
}

static inline void ipv6_build_hdr(lune_ipv6_hdr_t *ipv6h,
    const lune_ipv6_addr_t *src_addr,
    const lune_ipv6_addr_t *dst_addr,
    unsigned char trf_class,
    unsigned int flow_label,
    unsigned short payload_len,
    unsigned char next_hdr,
    unsigned char hop_limit)
{
    ipv6h->ver_tc_fl = lune_htonl((0x06 << 28) | (trf_class << 20) | flow_label);
    ipv6h->payload_len = lune_htons(payload_len);
    ipv6h->next_hdr = next_hdr;
    ipv6h->hop_limit = hop_limit;
    LUNE_IPV6_CPY(&ipv6h->src_addr, src_addr);
    LUNE_IPV6_CPY(&ipv6h->dst_addr, dst_addr);
}

/* defragmentation */
static inline int ipv6_defrag(pbuf_t *pbuf,
    pbuf_t **defrag_ppbuf,
    const lune_ipv6_addr_t *src_addr,
    const lune_ipv6_addr_t *dst_addr,
    unsigned short payload_len,
    const lune_ipv6_frag_hdr_t *ipv6fh)
{
    ipv6_defrag_t *defrag, defrag2;
    ipv6_frag_t *frag, *frag2, *new_frag;
    pbuf_t *new_pbuf;
    lune_ipv6_hdr_t *new_ipv6h;
    lune_ipv6_frag_hdr_t new_ipv6fh;
    unsigned short offset;
    int err;

    LUNE_IPV6_FRAG_HDR_CPY(&new_ipv6fh, ipv6fh);
    new_ipv6fh.offset = lune_ntohs(new_ipv6fh.offset);
    offset = new_ipv6fh.offset & LUNE_IPV6_FRAG_OFFSET;
    new_ipv6fh.id = lune_ntohl(new_ipv6fh.id);

    LUNE_IPV6_CPY(&defrag2.src_addr, src_addr);
    LUNE_IPV6_CPY(&defrag2.dst_addr, dst_addr);
    defrag2.id = new_ipv6fh.id;
    if (NULL == (defrag = htable_find((void *)&defrag2, s_ipv6_frag_htable))) {
        if (NULL == (defrag = ipv6_create_defrag(&defrag2.src_addr,
            &defrag2.dst_addr, defrag2.id, new_ipv6fh.next_hdr))) {
            goto ERR_1;
        }

        if (0 != (err = htable_insert((void *)defrag, s_ipv6_frag_htable, 1))) {
            goto ERR_2;
        }

        if (NULL == (new_frag = ipv6_create_frag(PBUF_GET_PAYLOAD(pbuf),
            PBUF_GET_PAYLOAD_LEN(pbuf), offset))) {
            goto ERR_3;
        }

        dlist_add_tail(&new_frag->node, &defrag->head);

        defrag->cur_len += PBUF_GET_PAYLOAD_LEN(pbuf);
        if (IPV6_IS_LAST_FRAG(&new_ipv6fh)) {
            defrag->total_len = offset + payload_len - LUNE_IPV6_FRAG_HDR_LEN;
        }

        return IPV6_DEFRAG_INCOMPLETE;
    }

    if (unlikely(defrag->next_hdr != new_ipv6fh.next_hdr)) {
        ERR_SET_ERR(LUNE_ERR_IP_TYPE_MISMATCH);
        goto ERR_3;
    }

    dlist_for_each_node_reverse(frag, &defrag->head, node) {
        if (frag->offset < offset) {
            if (frag->offset + frag->len > offset) {
                /* fragments overlap */
                ERR_SET_ERR(LUNE_ERR_IPV6_UNEXPECTED_FRAG);
                goto ERR_3;
            }
            break;
        }

        if (frag->offset == offset) {
            if (frag->len == (payload_len - LUNE_IPV6_FRAG_HDR_LEN)) {
                /* duplicate fragment */
                return IPV6_DEFRAG_INCOMPLETE;
            } else {
                ERR_SET_ERR(LUNE_ERR_IPV6_UNEXPECTED_FRAG);
                goto ERR_3;
            }
        }

        if (frag->offset < (offset + payload_len - LUNE_IPV6_FRAG_HDR_LEN)) {
            /* fragments overlap */
            ERR_SET_ERR(LUNE_ERR_IPV6_UNEXPECTED_FRAG);
            goto ERR_3;
        }
    }

    if (NULL == (new_frag = ipv6_create_frag(PBUF_GET_PAYLOAD(pbuf),
        PBUF_GET_PAYLOAD_LEN(pbuf), offset))) {
        goto ERR_3;
    }

    dlist_add_head(&new_frag->node, &frag->node);

    defrag->cur_len += PBUF_GET_PAYLOAD_LEN(pbuf);
    if (IPV6_IS_LAST_FRAG(&new_ipv6fh)) {
        defrag->total_len = offset + payload_len - LUNE_IPV6_FRAG_HDR_LEN;
    } else {
        if (0 == defrag->total_len) {
            return IPV6_DEFRAG_INCOMPLETE;
        }
    }

    if (defrag->cur_len < defrag->total_len) {
        return IPV6_DEFRAG_INCOMPLETE;
    } else if (defrag->cur_len > defrag->total_len) {
        ERR_SET_ERR(LUNE_ERR_IPV6_UNEXPECTED_FRAG);
        goto ERR_3;
    }

    /* all fragments have been collected, defragment them */
    if (NULL == (new_pbuf = pbuf_alloc_recv_pbuf(defrag->total_len, LUNE_IPV6_HDR_LEN))) {
        goto ERR_3;
    }

    new_ipv6h = (lune_ipv6_hdr_t *)pbuf_move_down(new_pbuf, LUNE_IPV6_HDR_LEN);
    offset = 0;
    dlist_for_each_node_safe(frag, frag2, &defrag->head, node) {
        /* verify if the packet is fragmented properly */
        if (frag->offset != offset) {
            goto ERR_4;
        }
        memcpy(PBUF_GET_PAYLOAD(new_pbuf) + offset, frag->payload, frag->len);
        offset += frag->len;
        dlist_del(&frag->node);
        ipv6_delete_frag(frag);
    }

    /* construct header of defragmented ipv6 packet */
    ipv6_build_hdr(new_ipv6h, src_addr, dst_addr,
        IPV6_DEFAULT_TRF_CLASS, IPV6_DEFAULT_FLOW_LABEL, defrag->total_len, ipv6fh->next_hdr, IPV6_DEFAULT_HOP_LIMIT);

    *defrag_ppbuf = new_pbuf;

    (void)htable_remove((void *)defrag, s_ipv6_frag_htable);
    ipv6_delete_defrag(defrag);

    return IPV6_DEFRAG_COMPLETE;

ERR_4:
    pbuf_free_pbuf(new_pbuf);

ERR_3:
    (void)htable_remove((void *)defrag, s_ipv6_frag_htable);

ERR_2:
    ipv6_delete_defrag(defrag);

ERR_1:
    return ERR_GET_LAST_ERR();
}

static void ipv6_defrag_timeout(ipv6_defrag_t *defrag)
{
    ipv6_frag_t *frag, *frag2;

    lune_assert(NULL != defrag);

    (void)htable_remove((void *)defrag, s_ipv6_frag_htable);

    dlist_for_each_node_safe(frag, frag2, &defrag->head, node) {
        dlist_del(&frag->node);
        ipv6_delete_frag(frag);
    }

    lune_free(defrag);
}

static int ipv6_frag_htable_hash(ipv6_defrag_t *defrag)
{
    return ((defrag->id + lune_ntohl(defrag->src_addr.addr[3])) & IPV6_FRAG_HTABLE_MASK);
}

static int ipv6_frag_htable_compare(ipv6_defrag_t *defrag1, ipv6_defrag_t *defrag2)
{
    return (!(defrag1->id == defrag2->id
        && !LUNE_IPV6_CMP(&defrag1->src_addr, &defrag2->src_addr)
        && !LUNE_IPV6_CMP(&defrag1->dst_addr, &defrag2->dst_addr)));
}

static inline unsigned short ipv6_get_frag_pkt_max_len(mac_t *macp)
{
    return ((mac_get_mtu(macp) - LUNE_IPV6_HDR_LEN - LUNE_IPV6_FRAG_HDR_LEN) & (~0x07));
}

static inline void ipv6_build_frag_hdr(lune_ipv6_frag_hdr_t *ipv6fh,
    unsigned char next_hdr,
    unsigned short offset,
    unsigned int id)
{
    ipv6fh->next_hdr = next_hdr;
    ipv6fh->rsvd = 0;
    ipv6fh->offset = lune_htons(offset);
    ipv6fh->id = lune_htonl(id);
}

static inline int ipv6_route(mac_t *macp, lune_mac_addr_t dst_mac,
    ip_t *ipv6p, const lune_ipv6_addr_t *dst_addr, pbuf_t *pbuf)
{
    void *nb;
    int err;
    lune_ip_addr_t addr;

    if (IPV6_IS_MULTICAST_IP(dst_addr)) {
        MAC_GET_IPV6_MC_MAC(dst_addr, dst_mac);
        return NB_RETRIEVE_SUCCESS;
    }

    addr.is_ipv6 = 1;
    LUNE_IPV6_CPY(&addr.ipv6, dst_addr);
    if (NULL == (nb = nb_lookup(&addr, ipv6p->ifp))) {
        /*
            send neighbor solicitation request and put packet on hold till
            response received
        */
        if (0 != (err = nb_request_and_cache_pkt(&addr, ipv6p, macp, pbuf))) {
            return err;
        }

        return NB_PKT_QUEUEING;
    }

    if (NB_IS_REQUESTING(nb)) {
        /*
            neighbor solicitation request already sent but still waiting
            for response
        */
        if (0 != (err = nb_cache_pkt(nb, macp, pbuf))) {
            return err;
        }

        return NB_PKT_QUEUEING;
    }

    LUNE_MAC_CPY(dst_mac, NB_GET_MAC(nb));
    return NB_RETRIEVE_SUCCESS;
}

static inline int ipv6_output_done(ip_t *ipv6p, pbuf_t *pbuf, const lune_ipv6_addr_t *dst_addr)
{
    int err;
    unsigned long long bytes;

    switch (ipv6p->lower_type) {
    case LUNE_ID_MAC:
    {
        lune_mac_addr_t dst_mac;
        int ret;
        mac_t *macp = (mac_t *)ipv6p->lower_entry;

        bytes = PBUF_GET_PAYLOAD_LEN(pbuf) + PBUF_GET_HDR_LEN(pbuf);
        ret = ipv6_route(macp, dst_mac, ipv6p, dst_addr, pbuf);
        if (ret != 0) {
            return ((ret > 0) ? 0 : ret);
        }

        if (unlikely(0 != (err = mac_output(macp,
            dst_mac, ETH_TYPE_IPV6_N, pbuf)))) {
            return err;
        }

        ipv6p->stats.pkt_out++;
        ipv6p->stats.byte_out += bytes;
        return 0;
    }
    default:
        return ERR_SET_ERR(LUNE_ERR_NOT_SUPPORTED);
    }
}

int ipv6_input(lune_id_type_en lower_type, void *lower_entry, pbuf_t *pbuf)
{
    const lune_ipv6_hdr_t *ipv6h;
    lune_eth_hdr_t *ethh;
    ip_t *ipv6p;
    ip_t ipv6;
    int err = 0, defrag_flag = 0, ip_socket_flag = 0;
    unsigned short payload_len, frag_hdr_len;
    lune_ip_addr_t addr;
    char ipv6_str[LUNE_IPV6_MAX_ADDR_STR_LEN];
    unsigned int ver_tc_fl;
    unsigned int skip_ipv6;
    pbuf_t *orig_pbuf = NULL;

    ipv6h = (const lune_ipv6_hdr_t *)PBUF_GET_PAYLOAD(pbuf);
    ver_tc_fl = lune_ntohl(ipv6h->ver_tc_fl);
    payload_len = lune_ntohs(ipv6h->payload_len);

    if (unlikely((ver_tc_fl >> 28) != 6)) {
        return ERR_SET_ERR(LUNE_ERR_IPV6_MALFORM_PKT);
    }

    switch (lower_type) {
    case LUNE_ID_MAC:
        if (NULL == lower_entry) {
            if (IPV6_IS_MULTICAST_IP(&ipv6h->dst_addr)
                && IPV6_IS_SOLICIT_NODE_MULTICAST_IP(&ipv6h->dst_addr)
                && LUNE_IP_PROTO_ICMPV6 == ipv6h->next_hdr) {
                /* neighbor discover: skip ipv6 layer */
                ICMPV6_GET_SOLICIT_TGT_ADDR((const unsigned char *)ipv6h + LUNE_IPV6_HDR_LEN, &ipv6.ipv6.ip);
                skip_ipv6 = 1;
            } else {
                LUNE_IPV6_CPY(&ipv6.ipv6.ip, &ipv6h->dst_addr);
                skip_ipv6 = 0;
            }
        } else {
            LUNE_IPV6_CPY(&ipv6.ipv6.ip, &ipv6h->dst_addr);
            skip_ipv6 = 0;
        }

        ipv6.flags = 0;
        IP_SET_IPV6(&ipv6);
        ipv6.lower_type = lower_type;
        ipv6.lower_entry = lower_entry;
        ipv6.ifp = NET_IF_GET_CURR_NET_IF();
        if (NULL == (ipv6p = htable_find((void *)&ipv6, g_ip_htable))) {
            if (IPV6_IS_MULTICAST_IP(&ipv6.ipv6.ip)) {
                /* multicast not supported yet */
                ;
            }

            return 0;
        }

        if (skip_ipv6) {
            goto SKIP_IPV6;
        }

        ethh = (lune_eth_hdr_t *)PBUF_GET_HDR(pbuf);
        /*
            do not verify checksum for performance's sake.
            checksum may have been verified in case of dpdk
            driver
        */
        addr.is_ipv6 = 1;
        LUNE_IPV6_CPY(&addr.ipv6, &ipv6h->src_addr);
        if (0 != (err = nb_upsert(ethh->src_mac,
            &addr, NET_IF_GET_CURR_NET_IF()))) {
            nb_log_error("failed to upsert neighbor", &addr, err);
            return err;
        }

        break;
    case LUNE_ID_SOCKET:
        /* ip over socket not supported yet */
        return ERR_SET_ERR(LUNE_ERR_NOT_SUPPORTED);
    default:
        return ERR_SET_ERR(LUNE_ERR_IPV6_INTERNAL);
    }

    if (NULL != ipv6p) {
        if (unlikely(IP_IS_DELETED(ipv6p))) {
            lune_log(LUNE_DBG, "received packet for deleted ip %s",
                lune_ipv6_to_str(&ipv6p->ipv6.ip, ipv6_str, LUNE_IPV6_MAX_ADDR_STR_LEN));
            return 0;
        }

        ipv6p->stats.pkt_in++;
        ipv6p->stats.byte_in += PBUF_GET_PAYLOAD_LEN(pbuf);
        if (IP_IS_SOCKET(ipv6p)) {
            if (LUNE_SOCKET_IPV6 == SOCKET_GET_TYPE(ipv6p->sk)) {
                /* ipv6 raw socket */
                ipv6_pcb_t *pcb;

                lune_assert(NULL != ipv6p->sk);
                pcb = &((socket_t *)ipv6p->sk)->pcb.ipv6;
                if (NULL == pcb->cb.recv) {
                    /*
                        once a socket is bound to a specific ipv6 address without setting
                        callback function, all packets on that ipv6 address will be simply
                        bypassed.
                    */
                    goto DONE;
                }

                /*
                    for ip raw socket, pass whole ip header with payload to registered
                    recv function
                */
                SOCKET_PUSH_CB_SK(ipv6p->sk);
                pcb->cb.recv(pcb->cb.data,
                    (const unsigned char *)ipv6h, PBUF_GET_PAYLOAD_LEN(pbuf));
                SOCKET_POP_CB_SK();

                goto DONE;
            }

#ifdef LUNE_DEBUG
            lune_assert(LUNE_SOCKET_IP == SOCKET_GET_TYPE(ipv6p->sk));
#endif
            /* ipv6 datagram socket */
            ip_socket_flag = 1;
        }
    }

SKIP_IPV6:
    frag_hdr_len = IPV6_IS_FRAG(ipv6h) ? LUNE_IPV6_FRAG_HDR_LEN : 0;
    (void)pbuf_move_up(pbuf, LUNE_IPV6_HDR_LEN + frag_hdr_len);
    if (payload_len < (PBUF_GET_PAYLOAD_LEN(pbuf) + frag_hdr_len)) {
        /* trim trailing of mac layer */
        pbuf_update_payload_len(pbuf, payload_len - frag_hdr_len);
    }

    if (IPV6_IS_FRAG(ipv6h)) {
        /* ipv6 fragment */
        orig_pbuf = pbuf;
        err =  ipv6_defrag(orig_pbuf, &pbuf, &ipv6h->src_addr, &ipv6h->dst_addr,
            payload_len, (const lune_ipv6_frag_hdr_t *)(ipv6h + 1));
        if (err < 0) {
            lune_log(LUNE_INFO, "failed to defragment ipv6 packet: %s", ERR_GET_ERR_STR(err));
            return err;
        } else if (IPV6_DEFRAG_INCOMPLETE == err) {
            return 0;
        }

        lune_assert(IPV6_DEFRAG_COMPLETE == err);
        ipv6h = (const lune_ipv6_hdr_t *)PBUF_GET_HDR(pbuf);
        defrag_flag = 1;
    }

    if (ip_socket_flag) {
        /* ipv6 datagram socket */
        ip_pcb_t *pcb;
        lune_ip_addr_t src_ip;

        lune_assert(NULL != ipv6p->sk);
        pcb = &((socket_t *)ipv6p->sk)->pcb.ip;
        if (NULL == pcb->cb.recvfrom) {
            /*
                once a socket is bound to a specific ipv6 address without setting
                callback function, all packets on that ipv6 address will be simply
                bypassed.
            */
            goto DONE;
        }

        src_ip.is_ipv6 = 1;
        LUNE_IPV6_CPY(&src_ip.ipv6, &ipv6h->src_addr);

        /*
            for ip datagram socket, pass source address, protocol along with payload
            to registered recvfrom function
        */
        SOCKET_PUSH_CB_SK(ipv6p->sk);
        pcb->cb.recvfrom(pcb->cb.data,
            &src_ip,
            ipv6h->next_hdr,
            (const unsigned char *)PBUF_GET_PAYLOAD(pbuf),
            PBUF_GET_PAYLOAD_LEN(pbuf));
        SOCKET_POP_CB_SK();

        goto DONE;
    }

    switch (ipv6h->next_hdr) {
    case LUNE_IP_PROTO_TCP:
        err = tcp_input(ipv6p, (const void *)ipv6h, pbuf);
        break;
    case LUNE_IP_PROTO_UDP:
        err = udp_input_unicast(ipv6p, (const void *)ipv6h, pbuf);
        break;
    case LUNE_IP_PROTO_ICMPV6:
        err = icmpv6_input(ipv6p, (const void *)ipv6h, pbuf);
        break;
    default:
        break;
    }

DONE:
    if (defrag_flag) {
        orig_pbuf->pkt_info = pbuf->pkt_info;
        if (PBUF_L4_TYPE_TCP == PBUF_GET_L4_TYPE(pbuf)) {
            orig_pbuf->tcp.data_len = pbuf->tcp.data_len;
        }
        pbuf_free_pbuf(pbuf);
    }

    return err;
}

int ipv6_output(ip_t *ipv6p,
    const lune_ipv6_addr_t *dst_addr, unsigned char proto, pbuf_t *pbuf)
{
    lune_ipv6_hdr_t *ipv6h;
    lune_ipv6_frag_hdr_t *ipv6fh;
    unsigned short hdr_len, total_payload_len, max_len, offset, left_len, t;
    int err;

    total_payload_len = PBUF_GET_HDR_LEN(pbuf) + PBUF_GET_PAYLOAD_LEN(pbuf);
    if ((total_payload_len + LUNE_IPV6_HDR_LEN) > mac_get_mtu(ipv6p->lower_entry)) {
        hdr_len = LUNE_IPV6_HDR_LEN + LUNE_IPV6_FRAG_HDR_LEN;
        (void)pbuf_move_down(pbuf, hdr_len);


        max_len = ipv6_get_frag_pkt_max_len(ipv6p->lower_entry);
        left_len = total_payload_len - max_len;
        t = LUNE_IPV6_FRAG_MF;
        pbuf_truncate_pbuf(pbuf, max_len);
    } else {
        hdr_len = LUNE_IPV6_HDR_LEN;
        (void)pbuf_move_down(pbuf, hdr_len);

        left_len = 0;
        t = 0;
    }

    pbuf->l3_len = hdr_len;
    PBUF_SET_L3_IPV6(pbuf);

    lune_assert(LUNE_ID_MAC == ipv6p->lower_type);

    ipv6h = (lune_ipv6_hdr_t *)PBUF_GET_HDR(pbuf);

    if (0 == left_len) {
        ipv6_build_hdr(ipv6h, &ipv6p->ipv6.ip, dst_addr, IPV6_DEFAULT_TRF_CLASS,
            IPV6_DEFAULT_FLOW_LABEL, PBUF_GET_PAYLOAD_LEN(pbuf), proto, IPV6_DEFAULT_HOP_LIMIT);
        return ipv6_output_done(ipv6p, pbuf, dst_addr);
    }

    /*
        fragmentation, just notice that pbuf payload will be modified as part of it overlaps
        with header of fragmented ipv6 packets
    */
    ipv6fh = (lune_ipv6_frag_hdr_t *)(ipv6h + 1);
    ipv6_build_hdr(ipv6h, &ipv6p->ipv6.ip, dst_addr, IPV6_DEFAULT_TRF_CLASS, IPV6_DEFAULT_FLOW_LABEL,
        PBUF_GET_PAYLOAD_LEN(pbuf) + LUNE_IPV6_FRAG_HDR_LEN, LUNE_IP_PROTO_IPV6_FRAG, IPV6_DEFAULT_HOP_LIMIT);
    ipv6_build_frag_hdr(ipv6fh, proto, t, ipv6p->ipv6.pkt_id);
    if (0 != (err = ipv6_output_done(ipv6p, pbuf, dst_addr))) {
        goto ERR_1;
    }

    offset = 0;
    while (left_len > max_len) {
        pbuf_rebase_pbuf(pbuf, left_len);
        (void)pbuf_move_down(pbuf, hdr_len);
        pbuf->l3_len = hdr_len;
        PBUF_SET_L3_IPV6(pbuf);
        ipv6h = (lune_ipv6_hdr_t *)PBUF_GET_HDR(pbuf);

        offset += max_len;
        pbuf_truncate_pbuf(pbuf, max_len);
        t = (offset & LUNE_IPV6_FRAG_OFFSET) | LUNE_IPV6_FRAG_MF;

        ipv6fh = (lune_ipv6_frag_hdr_t *)(ipv6h + 1);
        ipv6_build_hdr(ipv6h, &ipv6p->ipv6.ip, dst_addr, IPV6_DEFAULT_TRF_CLASS, IPV6_DEFAULT_FLOW_LABEL,
            PBUF_GET_PAYLOAD_LEN(pbuf) + LUNE_IPV6_FRAG_HDR_LEN, LUNE_IP_PROTO_IPV6_FRAG, IPV6_DEFAULT_HOP_LIMIT);
        ipv6_build_frag_hdr(ipv6fh, proto, t, ipv6p->ipv6.pkt_id);
        if (0 != (err = ipv6_output_done(ipv6p, pbuf, dst_addr))) {
            goto ERR_2;
        }

        left_len -= max_len;
    }

    if (left_len > 0) {
        pbuf_rebase_pbuf(pbuf, left_len);
        (void)pbuf_move_down(pbuf, hdr_len);
        pbuf->l3_len = hdr_len;
        PBUF_SET_L3_IPV6(pbuf);
        ipv6h = (lune_ipv6_hdr_t *)PBUF_GET_HDR(pbuf);

        offset += max_len;
        t = offset & LUNE_IPV6_FRAG_OFFSET;

        ipv6fh = (lune_ipv6_frag_hdr_t *)(ipv6h + 1);
        ipv6_build_hdr(ipv6h, &ipv6p->ipv6.ip, dst_addr, IPV6_DEFAULT_TRF_CLASS, IPV6_DEFAULT_FLOW_LABEL,
            PBUF_GET_PAYLOAD_LEN(pbuf) + LUNE_IPV6_FRAG_HDR_LEN, LUNE_IP_PROTO_IPV6_FRAG, IPV6_DEFAULT_HOP_LIMIT);
        ipv6_build_frag_hdr(ipv6fh, proto, t, ipv6p->ipv6.pkt_id);
        if (0 != (err = ipv6_output_done(ipv6p, pbuf, dst_addr))) {
            goto ERR_2;
        }
    }

    ipv6p->ipv6.pkt_id++;
    return 0;

ERR_2:
    ipv6p->ipv6.pkt_id++;

ERR_1:
    return err;
}

int ipv6_output_nofrag(ip_t *ipv6p,
    const lune_ipv6_addr_t *dst_addr, unsigned char proto, pbuf_t *pbuf)
{
    lune_ipv6_hdr_t *ipv6h;
    unsigned short hdr_len = LUNE_IPV6_HDR_LEN;

    ipv6h = (lune_ipv6_hdr_t *)pbuf_move_down(pbuf, hdr_len);

    pbuf->l3_len = hdr_len;
    PBUF_SET_L3_IPV6(pbuf);

#ifdef LUNE_DEBUG
    lune_assert(LUNE_ID_MAC == ipv6p->lower_type);
    lune_assert((PBUF_GET_PAYLOAD_LEN(pbuf) + hdr_len) <= mac_get_mtu(ipv6p->lower_entry));
#endif

    ipv6_build_hdr(ipv6h, &ipv6p->ipv6.ip, dst_addr, IPV6_DEFAULT_TRF_CLASS,
        IPV6_DEFAULT_FLOW_LABEL, PBUF_GET_PAYLOAD_LEN(pbuf), proto, IPV6_DEFAULT_HOP_LIMIT);
    return ipv6_output_done(ipv6p, pbuf, dst_addr);
}

static inline unsigned int ipv6_add_ipv6(const lune_ipv6_addr_t *ipv6,
    lune_id_type_en lower_type, void *lower_entry)
{
    ip_t *ipv6p;

    lune_assert(NULL != lower_entry);

    if (NULL == (ipv6p = lune_malloc(sizeof(ip_t)))) {
        goto ERR_1;
    }

    if (LUNE_INVALID_ID == (ipv6p->id = idlist_get_new_id(g_ip_idlist))) {
        goto ERR_2;
    }

    if (0 != idtable_insert(ipv6p->id, ipv6p, g_ip_idtable)) {
        goto ERR_3;
    }

    memset(&ipv6p->stats, 0x00, sizeof(lune_ip_stats_t));
    ipv6p->ref_cnt = 0;

    ipv6p->lower_entry = lower_entry;
    ipv6p->lower_type = lower_type;
    lower_entry_hold(lower_entry, lower_type);

    if (ip_get_mtu(ipv6p) < LUNE_IPV6_MIN_MTU) {
        ERR_SET_ERR(LUNE_ERR_INVALID_MTU);
        goto ERR_4;
    }

    LUNE_IPV6_CPY(ipv6p->ipv6.ip.addr, ipv6->addr);
    ipv6p->ipv6.pkt_id = lune_rand(0, 0xffffffff);

    ipv6p->sk = ipv6p->tcp_listen_sk = NULL;
    ipv6p->flags = 0;
    IP_SET_IPV6(ipv6p);
    if (LUNE_ID_MAC == lower_type
        && LUNE_ID_NET_IF == MAC_GET_LOWER_TYPE(lower_entry)) {
        ipv6p->ifp = MAC_GET_LOWER_ENTRY(lower_entry);
    } else {
        ipv6p->ifp = NULL;
    }

#ifdef LUNE_BUILD_DPDK
    if (lower_entry_is_dpdk(lower_entry, lower_type)) {
        IP_SET_DPDK(ipv6p);
    }
#endif

    if (0 != htable_insert((void *)ipv6p, g_ip_htable, 0)) {
        goto ERR_4;
    }

    IP_SET_ADDED(ipv6p);

    /* referenced by id table */
    ip_hold(ipv6p);
    /* referenced by hash table */
    ip_hold(ipv6p);

    return ipv6p->id;

ERR_4:
    lune_assert(!idtable_remove(ipv6p->id, g_ip_idtable));

    lower_entry_put(lower_entry, lower_type);

ERR_3:
    lune_assert(!idlist_del_id(ipv6p->id, g_ip_idlist));

ERR_2:
    lune_free(ipv6p);

ERR_1:
    return LUNE_INVALID_ID;
}

static inline int ipv6_del_ipv6(ip_t *ipv6p)
{
    IP_SET_DELETED(ipv6p);

    lune_assert(!htable_remove(ipv6p, g_ip_htable));

    lower_entry_put(ipv6p->lower_entry, ipv6p->lower_type);
    ipv6p->lower_entry = NULL;

    lune_assert(!idtable_remove(ipv6p->id, g_ip_idtable));
    lune_assert(!idlist_del_id(ipv6p->id, g_ip_idlist));

    /* de-referenced from hash table */
    ip_put(ipv6p);

    /* de-referenced from id table */
    ip_put(ipv6p);

    return 0;
}

unsigned int lune_add_ipv6(lune_ipv6_addr_t *ipv6,
    lune_id_type_en lower_type, unsigned int sub_id)
{
    void *lower_entry;

    SCHED_CHECK_POINT();

    if (LUNE_INVALID_ID == sub_id) {
        ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        return LUNE_INVALID_ID;
    }

    if (LUNE_ID_MAC != lower_type) {
        ERR_SET_ERR(LUNE_ERR_NOT_SUPPORTED);
        return LUNE_INVALID_ID;
    }

    if (NULL == (lower_entry = id_get_entry(lower_type, sub_id))) {
        ERR_SET_ERR(LUNE_ERR_ID_NOT_FOUND);
        return LUNE_INVALID_ID;
    }

    return ipv6_add_ipv6(ipv6, lower_type, lower_entry);
}

int lune_del_ipv6(unsigned int id)
{
    ip_t *ipv6p;

    SCHED_CHECK_POINT();

    if (LUNE_INVALID_ID == id) {
        return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
    }

    if (NULL == (ipv6p = idtable_find(id, g_ip_idtable))) {
        return ERR_SET_ERR(LUNE_ERR_ID_NOT_FOUND);
    }

    if (IP_IS_SOCKET(ipv6p)) {
        return ERR_SET_ERR(LUNE_ERR_NOT_CLOSED);
    }

    if (unlikely(!IP_IS_IPV6(ipv6p))) {
        return ERR_SET_ERR(LUNE_ERR_IP_TYPE_MISMATCH);
    }

    return ipv6_del_ipv6(ipv6p);
}

int lune_get_ipv6(lune_ipv6_addr_t *ipv6, lune_id_type_en lower_type, unsigned int sub_id, unsigned int *ip_id)
{
    ip_t *ipv6p;
    void *lower_entry;
    void *ifp;

    SCHED_CHECK_POINT();

    if (NULL == ip_id) {
        return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
    }

    if (LUNE_INVALID_ID == sub_id) {
        *ip_id = LUNE_INVALID_ID;
        return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
    }

    if (LUNE_ID_MAC != lower_type) {
        *ip_id = LUNE_INVALID_ID;
        return ERR_SET_ERR(LUNE_ERR_NOT_SUPPORTED);
    }

    if (NULL == (lower_entry = id_get_entry(lower_type, sub_id))) {
        *ip_id = LUNE_INVALID_ID;
        return ERR_SET_ERR(LUNE_ERR_ID_NOT_FOUND);
    }

    if (LUNE_ID_MAC == lower_type
        && LUNE_ID_NET_IF == MAC_GET_LOWER_TYPE(lower_entry)) {
        ifp = MAC_GET_LOWER_ENTRY(lower_entry);
    } else {
        ifp = NULL;
    }

    if (NULL == (ipv6p = ip_get_ip_by_addr((void *)ipv6,
        1, lower_type, lower_entry, ifp))) {
        *ip_id = LUNE_INVALID_ID;
        /* ERR_SET_ERR() unneeded */
        return -LUNE_ERR_NOT_EXIST;
    }

    *ip_id = ipv6p->id;
    return 0;
}

#define IPV6_ZERO_BLOCK_NONE        (0)
#define IPV6_ZERO_BLOCK_ONE_DONE    (1)
#define IPV6_ZERO_BLOCK_ONE_ONGOING (2)

char *lune_ipv6_to_str(const lune_ipv6_addr_t *addr, char *buf, unsigned int len)
{
    unsigned int curr_block_idx, curr_block_val, next_block_val;
    unsigned int i, zero_block_flag, zero_flag;

    if (unlikely(NULL == addr || NULL == buf || len < LUNE_IPV6_MAX_ADDR_STR_LEN)) {
        ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        return NULL;
    }

    zero_block_flag = IPV6_ZERO_BLOCK_NONE;
    for (i = 0, curr_block_idx = 0; curr_block_idx < 8; curr_block_idx++) {
        curr_block_val = lune_ntohl(addr->addr[curr_block_idx >> 1]);
        if (curr_block_idx & 0x01) {
            curr_block_val &= 0xffff;
        } else {
            curr_block_val = curr_block_val >> 16;
        }

        if (curr_block_val == 0) {
            if (curr_block_idx == 7 && zero_block_flag == IPV6_ZERO_BLOCK_ONE_ONGOING) {
                buf[i++] = ':';
                lune_assert(i < len);
                break;
            }

            if (zero_block_flag == IPV6_ZERO_BLOCK_NONE) {
                /*
                    generate "::" only if more than one contiguous zero block
                    according to rfc5952
                */
                next_block_val = lune_ntohl(addr->addr[(curr_block_idx + 1) >> 1]);
                if (curr_block_idx & 0x01) {
                    next_block_val = next_block_val >> 16;
                } else {
                    next_block_val &= 0xffff;
                }

                if (next_block_val == 0) {
                    zero_block_flag = IPV6_ZERO_BLOCK_ONE_ONGOING;
                    buf[i++] = ':';
                    lune_assert(i < len);
                    continue; /* move on to next block. */
                }
            } else if (zero_block_flag == IPV6_ZERO_BLOCK_ONE_ONGOING) {
                continue;
            }
        } else if (zero_block_flag == IPV6_ZERO_BLOCK_ONE_ONGOING) {
            /* Set this flag value so we don't produce multiple empty blocks. */
            zero_block_flag = IPV6_ZERO_BLOCK_ONE_DONE;
        }

        if (curr_block_idx > 0) {
            buf[i++] = ':';
            lune_assert(i < len);
        }

        if ((curr_block_val >> 12) == 0) {
            zero_flag = 1;
        } else {
            buf[i++] = LUNE_HEX_TO_CHAR(curr_block_val >> 12);
            zero_flag = 0;
            lune_assert(i < len);
        }

        if (((curr_block_val & 0x0f00) != 0) || !zero_flag) {
            buf[i++] = LUNE_HEX_TO_CHAR(((curr_block_val & 0x0f00) >> 8));
            zero_flag = 0;
            lune_assert(i < len);
        }

        if (((curr_block_val & 0x00f0) != 0) || !zero_flag) {
            buf[i++] = LUNE_HEX_TO_CHAR(((curr_block_val & 0x00f0) >> 4));
            zero_flag = 0;
            lune_assert(i < len);
        }

        buf[i++] = LUNE_HEX_TO_CHAR((curr_block_val & 0x000f));
        lune_assert(i < len);
    }

    buf[i] = 0;

    return buf;
}

int lune_str_to_ipv6(const char *str, lune_ipv6_addr_t *addr)
{
    int zero_blocks;
    unsigned int zero_block_flag, addr_idx, curr_block_idx, curr_block_val, digit_cnt;
    const char *p;

    if (unlikely(NULL == str || NULL == addr)) {
        return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
    }

    p = str;
    if (*p == ':') {
        if (*(p + 1) != ':') {
            return ERR_SET_ERR(LUNE_ERR_MALFORMED_ARG);
        }
        digit_cnt = 0;
    } else if (!LUNE_IS_HEX_CHAR(*p)) {
        return ERR_SET_ERR(LUNE_ERR_MALFORMED_ARG);
    } else {
        digit_cnt = 1;
    }

    zero_blocks = 7;
    zero_block_flag = 0;
    for (p++; *p != 0; p++) {
        if (*p == ':') {
            digit_cnt = 0;
            if (*(p - 1) == ':') {
                if (zero_block_flag) {
                    return ERR_SET_ERR(LUNE_ERR_MALFORMED_ARG);
                } else {
                    zero_block_flag = 1;
                }
            } else {
                if (--zero_blocks < 0) {
                    return ERR_SET_ERR(LUNE_ERR_MALFORMED_ARG);
                }
            }
        } else if (!LUNE_IS_HEX_CHAR(*p)) {
            return ERR_SET_ERR(LUNE_ERR_MALFORMED_ARG);
        } else {
            if (++digit_cnt > 4) {
                return ERR_SET_ERR(LUNE_ERR_MALFORMED_ARG);
            }
        }
    }

    if (*(p - 1) == ':') {
        if (*(p - 2) == ':') {
            zero_blocks++;
        } else {
            return ERR_SET_ERR(LUNE_ERR_MALFORMED_ARG);
        }
    }

    if (zero_blocks > 0 && !zero_block_flag) {
        return ERR_SET_ERR(LUNE_ERR_MALFORMED_ARG);
    }

    addr_idx = curr_block_idx = curr_block_val = 0;
    for (p = str; *p != 0; p++) {
        if (*p == ':') {
            if (p != str) {
                if (curr_block_idx & 0x01) {
                    addr->addr[addr_idx++] |= curr_block_val;
                } else {
                    addr->addr[addr_idx] = curr_block_val << 16;
                }

                curr_block_idx++;
                curr_block_val = 0;
            }

            if (p[1] == ':') {
                p++;
                while (zero_blocks > 0) {
                    zero_blocks--;
                    if (curr_block_idx & 0x01) {
                        addr_idx++;
                    } else {
                        addr->addr[addr_idx] = 0;
                    }
                    curr_block_idx++;
                }
            }
        } else if (LUNE_IS_HEX_CHAR(*p)) {
            curr_block_val = (curr_block_val << 4) + LUNE_CHAR_TO_HEX(*p);
        } else {
            lune_assert(0);
            return ERR_SET_ERR(LUNE_ERR_MALFORMED_ARG);
        }
    }

    if (curr_block_idx > 8
        || curr_block_idx < 7
        || (curr_block_idx == 8
        && str[0] != ':' && *(p - 1) != ':')) {
        return ERR_SET_ERR(LUNE_ERR_MALFORMED_ARG);
    }

    if (curr_block_idx & 0x01) {
        addr->addr[addr_idx++] |= curr_block_val;
    } else {
        addr->addr[addr_idx] = curr_block_val << 16;
    }

    for (addr_idx = 0; addr_idx < 4; addr_idx++) {
        addr->addr[addr_idx] = lune_htonl(addr->addr[addr_idx]);
    }

    return 0;
}

unsigned short ipv6_get_max_hdr_len(ip_t *ipv6p)
{
    unsigned short lower_entry_hdr_len;

    lune_assert(NULL != ipv6p);

    lower_entry_hdr_len = pbuf_get_max_hdr_len(ipv6p->lower_type, ipv6p->lower_entry);
    return IPV6_MAX_HDR_LEN + lower_entry_hdr_len;
}

static int ipv6_socket_create(socket_t *sk)
{
    ipv6_pcb_t *pcb = &sk->pcb.ipv6;

    pcb->cb.recv = NULL;
    pcb->cb.data = NULL;
    pcb->ipv6p = NULL;

    return 0;
}

static int ipv6_socket_bind(socket_t *sk, const void *arg, unsigned int arg_len)
{
    ip_t *ipv6p;
    ipv6_pcb_t *pcb;

    if (arg_len != sizeof(unsigned int)) {
        return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
    }

    pcb = &sk->pcb.ipv6;
    if (NULL != pcb->ipv6p) {
        return ERR_SET_ERR(LUNE_ERR_ALREADY_BOUND);
    }

    if (NULL == (ipv6p = ip_get_ip_by_id(*(const unsigned int *)arg))) {
        return ERR_SET_ERR(LUNE_ERR_ID_NOT_FOUND);
    }

    if (IP_IS_SOCKET(ipv6p) || IP_L4_SOCKET_EXIST(ipv6p)) {
        return ERR_SET_ERR(LUNE_ERR_ALREADY_BOUND);
    }

    /*
        it is not necessary to ip_hold(ipv6p) because ipv6p cannot be deleted until socket is close
    */
    pcb->ipv6p = ipv6p;

    IP_SET_SOCKET(ipv6p);
    /*
        it is not necessary to socket_hold(sk) because ipv6p->sk exists only within the lifetime of socket
    */
    ipv6p->sk = sk;
    sk->rsvd_hdr_len = ipv6_get_max_hdr_len(ipv6p);

    return 0;
}

static int ipv6_socket_sendto(socket_t *sk, const unsigned char *buf, unsigned int len,
    lune_ipv6_addr_t *dst_addr, unsigned int dst_addr_len,
    lune_ipv6_sendto_arg_t *arg, unsigned int arg_len)
{
    ipv6_pcb_t *pcb;
    unsigned char lbuf[PBUF_MAX_RSVD_HDR_LEN + LUNE_NET_IF_MAX_MTU];
    pbuf_t pbuf;
    unsigned short hdr_len;
    lune_ipv6_hdr_t *ipv6h;

    if (unlikely(dst_addr_len != sizeof(lune_ipv6_addr_t)
        || NULL == arg
        || arg_len != sizeof(lune_ipv6_sendto_arg_t)
        || arg->flow_label > LUNE_IPV6_MAX_FLOW_LABEL)) {
        return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
    }

    pcb = &sk->pcb.ipv6;

    lune_assert(LUNE_ID_MAC == pcb->ipv6p->lower_type);
    if (unlikely(LUNE_IPV6_HDR_LEN + len > ((mac_t *)(pcb->ipv6p->lower_entry))->mtu)) {
        return ERR_SET_ERR(LUNE_ERR_OVERSIZED_PKT);
    }

    if (unlikely(NULL == pcb->ipv6p)) {
        return ERR_SET_ERR(LUNE_ERR_NOT_BOUND);
    }

    pbuf_init_send_pbuf(&pbuf, lbuf, len, PBUF_MAX_RSVD_HDR_LEN, IP_IS_DPDK(pcb->ipv6p));
    if (likely(len > 0)) {
        memcpy(PBUF_GET_HDR(&pbuf), buf, len);
    }
    hdr_len = LUNE_IPV6_HDR_LEN;
    ipv6h = (lune_ipv6_hdr_t *)pbuf_move_down(&pbuf, hdr_len);

    ipv6_build_hdr(ipv6h, &pcb->ipv6p->ipv6.ip, dst_addr,
        arg->trf_class, arg->flow_label, arg->payload_len, arg->next_hdr, arg->hop_limit);

    return ipv6_output_done(pcb->ipv6p, &pbuf, dst_addr);
}

static int ipv6_socket_get_opt(socket_t *sk, lune_socket_opt_en opt, unsigned char *opt_val, unsigned int opt_len)
{
    ipv6_pcb_t *pcb = &sk->pcb.ipv6;

    switch (opt) {
    case LUNE_SOCKET_OPT_GET_SRC_IP_ID:
        if (unlikely(NULL == opt_val || opt_len != sizeof(unsigned int))) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        if (NULL == pcb->ipv6p) {
            return ERR_SET_ERR(LUNE_ERR_NOT_BOUND);
        }

        *(unsigned int *)opt_val = pcb->ipv6p->id;
        break;
    default:
        return ERR_SET_ERR(LUNE_ERR_OPT_NOT_FOUND);
    }

    return 0;
}

static int ipv6_socket_set_opt(socket_t *sk,
    lune_socket_opt_en opt, const unsigned char *opt_val, unsigned int opt_len)
{
    ipv6_pcb_t *pcb = &sk->pcb.ipv6;

    switch (opt) {
    case LUNE_SOCKET_OPT_SET_CALLBACK:
        if (NULL == opt_val
            || opt_len != sizeof(lune_ipv6_socket_callback_t)) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        pcb->cb.recv = ((const lune_ipv6_socket_callback_t *)opt_val)->recv;
        pcb->cb.data = ((const lune_ipv6_socket_callback_t *)opt_val)->data;
        break;
    default:
        return ERR_SET_ERR(LUNE_ERR_OPT_NOT_FOUND);
    }

    return 0;
}

static int ipv6_socket_close(socket_t *sk)
{
    ip_t *ipv6p;
    ipv6_pcb_t *pcb = &sk->pcb.ipv6;

    pcb->cb.recv = NULL;

    ipv6p = pcb->ipv6p;
    if (NULL != ipv6p) {
        IP_SET_NON_SOCK(ipv6p);
        ipv6p->sk = NULL;
        pcb->ipv6p = NULL;
    }

    return 0;
}

static unsigned short ipv6_socket_get_max_hdr_len(socket_t *sk)
{
    ip_t *ipv6p = sk->pcb.ipv6.ipv6p;

    lune_assert(LUNE_ID_MAC == ipv6p->lower_type);

    return ipv6_get_max_hdr_len(ipv6p);
}

socket_ops_t g_socket_ops_ipv6 = {
    .create = (socket_create_func_t)ipv6_socket_create,
    .bind = (socket_bind_func_t)ipv6_socket_bind,
    .connect = NULL,
    .listen = NULL,
    .send = NULL,
    .send_pkts = NULL,
    .sendto = (socket_sendto_func_t)ipv6_socket_sendto,
    .get_opt = (socket_get_opt_func_t)ipv6_socket_get_opt,
    .set_opt = (socket_set_opt_func_t)ipv6_socket_set_opt,
    .close = (socket_close_func_t)ipv6_socket_close,
    .hash = NULL,
    .compare = NULL,
    .get_max_hdr_len = (socket_get_max_hdr_len_func_t)ipv6_socket_get_max_hdr_len,
};

int ipv6_local_init(void)
{
    if (NULL == (s_ipv6_frag_htable = htable_create_table("ipv6 fragment hash table",
        (htable_hash_func_t)ipv6_frag_htable_hash,
        (htable_compare_func_t)ipv6_frag_htable_compare,
        (htable_free_func_t)ipv6_delete_defrag,
        offsetof(ipv6_defrag_t, node),
        IPV6_FRAG_HTABLE_SIZE,
        0))) {
        return ERR_GET_LAST_ERR();
    }

    return 0;
}

void ipv6_local_fini(void)
{
    lune_assert(!htable_delete_table(s_ipv6_frag_htable));
    s_ipv6_frag_htable = NULL;
}
