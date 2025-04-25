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
#include "net/arp.h"
#include "net/icmp.h"
#include "net/id.h"
#include "net/igmp.h"
#include "net/ip.h"
#include "net/mac.h"
#include "net/nb.h"
#include "net/pbuf.h"
#include "net/socket.h"
#include "net/tcp.h"
#include "net/udp.h"

#define IPV4_FRAG_HTABLE_SIZE_IN_BIT    (18)
#define IPV4_FRAG_HTABLE_SIZE           (1 << (IPV4_FRAG_HTABLE_SIZE_IN_BIT))
#define IPV4_FRAG_HTABLE_MASK           (IPV4_FRAG_HTABLE_SIZE - 1)

#define IPV4_MAX_HDR_LEN                (60)
#define IPV4_DEFAULT_TOS                (0)
#define IPV4_DEFAULT_TTL                (128)

#define IPV4_IS_VALID_MASK(mask)   (!((~(mask)) & ((~(mask)) + 1)))

#define IPV4_DEFRAG_TIMEOUT             (LUNE_TIME_SECOND * 5)

#pragma pack(1)
typedef struct _ipv4_frag {
    dlist_node_t node;
    unsigned short offset;
    unsigned short len;
    unsigned int rsvd;  /* reserved for memory alignment */
    unsigned char payload[0];
} ipv4_frag_t;
#pragma pack()

typedef struct _ipv4_defrag {
    dlist_head_t head;
    dlist_node_t node;
    lune_timer_t tmr;
    lune_ipv4_addr_t src_addr;
    lune_ipv4_addr_t dst_addr;
    unsigned short id;
    unsigned char proto;
    unsigned short total_len;
    unsigned short cur_len;
} ipv4_defrag_t;

static __thread void *s_ipv4_frag_htable = NULL;

static inline unsigned int ipv4_add_ipv4(const lune_ipv4_addr_t ipv4,
    lune_ipv4_addr_t mask, lune_ipv4_addr_t gw, lune_id_type_en sub_type, void *sub_entry)
{
    ip_t *ipv4p;

    lune_assert(NULL != sub_entry);

    if (NULL == (ipv4p = lune_malloc(sizeof(ip_t)))) {
        goto ERR_1;
    }

    if (LUNE_INVALID_ID == (ipv4p->id = idlist_get_new_id(g_ip_idlist))) {
        goto ERR_2;
    }

    if (0 != idtable_insert(ipv4p->id, ipv4p, g_ip_idtable)) {
        goto ERR_3;
    }

    memset(&ipv4p->stats, 0x00, sizeof(lune_ip_stats_t));
    ipv4p->ref_cnt = 0;

    ipv4p->sub_entry = sub_entry;
    ipv4p->sub_type = sub_type;
    sub_entry_hold(sub_entry, sub_type);

    ipv4p->ipv4.ip = ipv4;
    ipv4p->ipv4.mask = mask;
    ipv4p->ipv4.gw = gw;
    dlist_init_head(&ipv4p->ipv4.gw_list);
    ipv4p->ipv4.pkt_id = (unsigned short)lune_rand(0, 65535);

    ipv4p->sk = ipv4p->tcp_listen_sk = NULL;
    ipv4p->flags = 0;   /* IP_SET_IPV4() included */
    if (LUNE_ID_MAC == sub_type
        && LUNE_ID_NET_IF == MAC_GET_SUB_TYPE(sub_entry)) {
        ipv4p->ifp = MAC_GET_SUB_ENTRY(sub_entry);
    } else {
        ipv4p->ifp = NULL;
    }
    /*
        ip_set_net_if_hw_csum_flags MUST be called after ifp
        being initialized
    */
    ip_set_net_if_hw_csum_flags(ipv4p);

#ifdef LUNE_BUILD_DPDK
    if (sub_entry_is_dpdk(sub_entry, sub_type)) {
        IP_SET_DPDK(ipv4p);
    }
#endif

    if (0 != htable_insert((void *)ipv4p, g_ip_htable, 0)) {
        goto ERR_4;
    }

    IP_SET_ADDED(ipv4p);

    /* referenced by id table */
    ip_hold(ipv4p);
    /* referenced by hash table */
    ip_hold(ipv4p);

    return ipv4p->id;

ERR_4:
    lune_assert(!idtable_remove(ipv4p->id, g_ip_idtable));

    sub_entry_put(sub_entry, sub_type);

ERR_3:
    lune_assert(!idlist_del_id(ipv4p->id, g_ip_idlist));

ERR_2:
    lune_free(ipv4p);

ERR_1:
    return LUNE_INVALID_ID;
}

static inline int ipv4_del_ipv4(ip_t *ipv4p)
{
    IP_SET_DELETED(ipv4p);

    lune_assert(!htable_remove(ipv4p, g_ip_htable));

    sub_entry_put(ipv4p->sub_entry, ipv4p->sub_type);
    ipv4p->sub_entry = NULL;

    lune_assert(!idtable_remove(ipv4p->id, g_ip_idtable));
    lune_assert(!idlist_del_id(ipv4p->id, g_ip_idlist));

    /* de-referenced from hash table */
    ip_put(ipv4p);

    /* de-referenced from id table */
    ip_put(ipv4p);

    return 0;
}

static inline ipv4_frag_t *ipv4_create_frag(unsigned char *buf, unsigned short len, unsigned short offset)
{
    ipv4_frag_t *frag;

    lune_assert(NULL != buf);
    lune_assert(offset <= LUNE_IPV4_FRAG_OFFSET);
    lune_assert(len > 0);

    if (NULL == (frag = lune_malloc(sizeof(ipv4_frag_t) + len))) {
        return NULL;
    }

    dlist_init_node(&frag->node);
    frag->offset = offset;
    frag->len = len;
    memcpy(frag->payload, buf, len);

    return frag;
}

static inline void ipv4_delete_frag(ipv4_frag_t *frag)
{
    lune_free(frag);
}

static void ipv4_defrag_timeout(ipv4_defrag_t *defrag);

static inline ipv4_defrag_t *ipv4_create_defrag(lune_ipv4_addr_t src_addr,
    lune_ipv4_addr_t dst_addr,
    unsigned short id,
    unsigned char proto)
{
    ipv4_defrag_t *defrag;

    if (NULL == (defrag = lune_malloc(sizeof(ipv4_defrag_t)))) {
        return NULL;
    }

    dlist_init_head(&defrag->head);
    dlist_init_node(&defrag->node);
    timer_init_timer(&defrag->tmr,
        LUNE_TIMER_ONCE, LUNE_TIMER_RES_HIGH, (lune_timer_func_t)ipv4_defrag_timeout, defrag);
    defrag->src_addr = src_addr;
    defrag->dst_addr = dst_addr;
    defrag->id = id;
    defrag->proto = proto;
    defrag->cur_len = 0;
    defrag->total_len = 0;

    timer_add_timer(&defrag->tmr, IPV4_DEFRAG_TIMEOUT);

    return defrag;
}

static inline void ipv4_delete_defrag(ipv4_defrag_t *defrag)
{
    ipv4_frag_t *frag, *frag2;

    lune_assert(NULL != defrag);

    dlist_for_each_node_safe(frag, frag2, &defrag->head, node) {
        dlist_del(&frag->node);
        ipv4_delete_frag(frag);
    }

    (void)timer_del_timer(&defrag->tmr);

    lune_free(defrag);
}

static void ipv4_defrag_timeout(ipv4_defrag_t *defrag)
{
    ipv4_frag_t *frag, *frag2;

    lune_assert(NULL != defrag);

    (void)htable_remove((void *)defrag, s_ipv4_frag_htable);

    dlist_for_each_node_safe(frag, frag2, &defrag->head, node) {
        dlist_del(&frag->node);
        ipv4_delete_frag(frag);
    }

    lune_free(defrag);
}

static int ipv4_frag_htable_hash(ipv4_defrag_t *defrag)
{
    return ((defrag->id + defrag->src_addr + defrag->dst_addr) & IPV4_FRAG_HTABLE_MASK);
}

static int ipv4_frag_htable_compare(ipv4_defrag_t *defrag1, ipv4_defrag_t *defrag2)
{
    return (!(defrag1->id == defrag2->id
        && defrag1->src_addr == defrag2->src_addr
        && defrag1->dst_addr == defrag2->dst_addr
        && defrag1->proto == defrag2->proto));
}

static inline void ipv4_dup_and_n2h_hdr(lune_ipv4_max_hdr_t *new_ipv4h, lune_ipv4_hdr_t *old_ipv4h)
{
    /* old_ipv4h may not be 8-byte aligned */
    *(unsigned short *)new_ipv4h = *(unsigned short *)old_ipv4h;
    new_ipv4h->hdr.total_len = lune_ntohs(old_ipv4h->total_len);
    new_ipv4h->hdr.id = lune_ntohs(old_ipv4h->id);
    new_ipv4h->hdr.offset = lune_ntohs(old_ipv4h->offset);
    *(unsigned short *)&new_ipv4h->hdr.ttl = *(unsigned short *)&old_ipv4h->ttl;
    new_ipv4h->hdr.csum = old_ipv4h->csum;
    new_ipv4h->hdr.src_addr = lune_ntohl(old_ipv4h->src_addr);
    new_ipv4h->hdr.dst_addr = lune_ntohl(old_ipv4h->dst_addr);
    /* TODO: ipv4 options in header, not supported */
}

#define IPV4_IS_FRAG(ipv4h)             \
    (((lune_ipv4_hdr_t *)(ipv4h))->offset & (LUNE_IPV4_FLAG_MF | LUNE_IPV4_FRAG_OFFSET))
#define IPV4_IS_LAST_FRAG(ipv4h)        \
    (((((lune_ipv4_hdr_t *)(ipv4h))->offset) & LUNE_IPV4_FLAG_MF) == 0)
/* ipv4h MUST be last fragment */
#define IPV4_GET_FRAG_TOTAL_LEN(ipv4h)  \
    ((((((lune_ipv4_hdr_t *)(ipv4h))->offset) & LUNE_IPV4_FRAG_OFFSET) << 3)    \
    + ((lune_ipv4_hdr_t *)(ipv4h))->total_len - IPV4_GET_HDR_LEN(ipv4h))

#define IPV4_DEFRAG_COMPLETE    (0)
#define IPV4_DEFRAG_INCOMPLETE  (1)

/* defragmentation */
static inline int ipv4_defrag(pbuf_t *pbuf, pbuf_t **defrag_ppbuf, lune_ipv4_hdr_t *ipv4h)
{
    ipv4_defrag_t *defrag, defrag2;
    ipv4_frag_t *frag, *frag2, *new_frag;
    unsigned short offset, hdr_len;
    pbuf_t *new_pbuf;
    lune_ipv4_hdr_t *new_ipv4h;
    int err;

    offset = ipv4h->offset & LUNE_IPV4_FRAG_OFFSET;

    defrag2.src_addr = ipv4h->src_addr;
    defrag2.dst_addr = ipv4h->dst_addr;
    defrag2.id = ipv4h->id;
    defrag2.proto = ipv4h->proto;
    if (NULL == (defrag = htable_find((void *)&defrag2, s_ipv4_frag_htable))) {
        if (NULL == (defrag = ipv4_create_defrag(defrag2.src_addr,
            defrag2.dst_addr,
            defrag2.id,
            defrag2.proto))) {
            goto ERR_1;
        }

        if (0 != (err = htable_insert((void *)defrag, s_ipv4_frag_htable, 1))) {
            goto ERR_2;
        }

        if (NULL == (new_frag = ipv4_create_frag(PBUF_GET_PAYLOAD(pbuf), PBUF_GET_PAYLOAD_LEN(pbuf), offset))) {
            goto ERR_3;
        }

        dlist_add_tail(&new_frag->node, &defrag->head);

        defrag->cur_len += PBUF_GET_PAYLOAD_LEN(pbuf);
        if (IPV4_IS_LAST_FRAG(ipv4h)) {
            defrag->total_len = IPV4_GET_FRAG_TOTAL_LEN(ipv4h);
        }

        return IPV4_DEFRAG_INCOMPLETE;
    }

    hdr_len = IPV4_GET_HDR_LEN(ipv4h);
    dlist_for_each_node_reverse(frag, &defrag->head, node) {
        if (frag->offset < offset) {
            if ((frag->offset << 3) + frag->len > (offset << 3)) {
                /* fragments overlap */
                ERR_SET_ERR(LUNE_ERR_IPV4_UNEXPECTED_FRAG);
                goto ERR_3;
            }
            break;
        }

        if (frag->offset == offset) {
            if (frag->len == (ipv4h->total_len - hdr_len)) {
                /* duplicate fragment */
                return IPV4_DEFRAG_INCOMPLETE;
            } else {
                ERR_SET_ERR(LUNE_ERR_IPV4_UNEXPECTED_FRAG);
                goto ERR_3;
            }
        }

        if (frag->offset < (offset + ipv4h->total_len - hdr_len)) {
            /* fragments overlap */
            ERR_SET_ERR(LUNE_ERR_IPV4_UNEXPECTED_FRAG);
            goto ERR_3;
        }
    }

    if (NULL == (new_frag = ipv4_create_frag(PBUF_GET_PAYLOAD(pbuf), PBUF_GET_PAYLOAD_LEN(pbuf), offset))) {
        goto ERR_3;
    }

    dlist_add_head(&new_frag->node, &frag->node);

    defrag->cur_len += PBUF_GET_PAYLOAD_LEN(pbuf);
    if (IPV4_IS_LAST_FRAG(ipv4h)) {
        defrag->total_len = IPV4_GET_FRAG_TOTAL_LEN(ipv4h);
    } else {
        if (0 == defrag->total_len) {
            return IPV4_DEFRAG_INCOMPLETE;
        }
    }

    if (defrag->cur_len < defrag->total_len) {
        /* refresh defragmentation timeout */
        timer_mod_timer(&defrag->tmr, IPV4_DEFRAG_TIMEOUT);
        return IPV4_DEFRAG_INCOMPLETE;
    } else if (defrag->cur_len > defrag->total_len) {
        ERR_SET_ERR(LUNE_ERR_IPV4_UNEXPECTED_FRAG);
        goto ERR_3;
    }

    /* all fragments have been collected, defragment them */
    if (NULL == (new_pbuf = pbuf_alloc_recv_pbuf(defrag->total_len, hdr_len))) {
        goto ERR_3;
    }

    new_ipv4h = (lune_ipv4_hdr_t *)pbuf_move_down(new_pbuf, hdr_len);
    offset = 0;
    dlist_for_each_node_safe(frag, frag2, &defrag->head, node) {
        /* verify if the packet is fragmented properly */
        if ((frag->offset << 3) != offset) {
            goto ERR_4;
        }
        memcpy(PBUF_GET_PAYLOAD(new_pbuf) + offset, frag->payload, frag->len);
        offset += frag->len;
        dlist_del(&frag->node);
        ipv4_delete_frag(frag);
    }

    /* construct header of defragmented ipv4 packet */
    new_ipv4h->ver_len = ipv4h->ver_len;
    new_ipv4h->tos = ipv4h->tos;
    new_ipv4h->total_len = defrag->total_len;
    new_ipv4h->id = ipv4h->id;
    new_ipv4h->offset = LUNE_IPV4_FLAG_DF;
    new_ipv4h->ttl = ipv4h->ttl;
    new_ipv4h->proto = ipv4h->proto;
    new_ipv4h->csum = 0;
    new_ipv4h->src_addr = ipv4h->src_addr;
    new_ipv4h->dst_addr = ipv4h->dst_addr;

    *defrag_ppbuf = new_pbuf;

    (void)htable_remove((void *)defrag, s_ipv4_frag_htable);
    ipv4_delete_defrag(defrag);

    return IPV4_DEFRAG_COMPLETE;

ERR_4:
    pbuf_free_pbuf(new_pbuf);

ERR_3:
    (void)htable_remove((void *)defrag, s_ipv4_frag_htable);

ERR_2:
    ipv4_delete_defrag(defrag);

ERR_1:
    return ERR_GET_LAST_ERR();
}

int ipv4_input(lune_id_type_en sub_type, void *sub_entry, pbuf_t *pbuf)
{
    lune_ipv4_hdr_t *n_ipv4h;
    lune_ipv4_max_hdr_t h_ipv4h;
    lune_eth_hdr_t *ethh;
    ip_t *ipv4p;
    ip_t ipv4;
    int err = 0, defrag_flag = 0, multicast_flag = 0, ip_socket_flag = 0;
    unsigned short hdr_len;
    igmp_group_t *igp;
    pbuf_t *orig_pbuf = NULL;
    lune_ip_addr_t addr;
    char ipv4_str[LUNE_IPV4_MAX_ADDR_STR_LEN];

    n_ipv4h = (lune_ipv4_hdr_t *)PBUF_GET_PAYLOAD(pbuf);

    switch (sub_type) {
    case LUNE_ID_MAC:
        ipv4_dup_and_n2h_hdr(&h_ipv4h, n_ipv4h);
        if (unlikely((h_ipv4h.hdr.ver_len & 0xf0) != 0x40)) {
            return ERR_SET_ERR(LUNE_ERR_IPV4_MALFORM_PKT);
        }

        if (NULL == sub_entry) {
            if (IPV4_IS_BROADCAST_IP(h_ipv4h.hdr.dst_addr)) {
                /* broadcast not supported yet */
                return 0;
            } else if (IPV4_IS_MULTICAST_IP(h_ipv4h.hdr.dst_addr)) {
                multicast_flag = 1;
                ipv4p = NULL;
                break;
            }

            return 0;
        }

        ipv4.flags = 0;     /* IP_SET_IPV4() included */
        ipv4.ipv4.ip = h_ipv4h.hdr.dst_addr;
        ipv4.sub_type = sub_type;
        ipv4.sub_entry = sub_entry;
        ipv4.ifp = NET_IF_GET_CURR_NET_IF();
        if (NULL == (ipv4p = htable_find((void *)&ipv4, g_ip_htable))) {
            if (IPV4_IS_BROADCAST_IP(h_ipv4h.hdr.dst_addr)
                || IPV4_IS_MULTICAST_IP(h_ipv4h.hdr.dst_addr)) {
                /* broadcast and multicast not supported yet */
                ;
            }

            return 0;
        }

        ethh = (lune_eth_hdr_t *)PBUF_GET_HDR(pbuf);
        /*
            do not verify checksum for performance's sake.
            checksum may have been verified in case of dpdk
            driver
        */
        addr.is_ipv6 = 0;
        addr.ipv4 = h_ipv4h.hdr.src_addr;
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
        return ERR_SET_ERR(LUNE_ERR_IPV4_INTERNAL);
    }

    if (NULL != ipv4p) {
        if (unlikely(IP_IS_DELETED(ipv4p))) {
            lune_log(LUNE_DBG, "received packet for deleted ip %s",
                lune_ipv4_to_str(ipv4p->ipv4.ip, ipv4_str, LUNE_IPV4_MAX_ADDR_STR_LEN));
            return 0;
        }

        ipv4p->stats.pkt_in++;
        ipv4p->stats.byte_in += PBUF_GET_PAYLOAD_LEN(pbuf);
        if (IP_IS_SOCKET(ipv4p)) {
            if (LUNE_SOCKET_IPV4 == SOCKET_GET_TYPE(ipv4p->sk)) {
                /* ipv4 raw socket */
                ipv4_pcb_t *pcb;

                lune_assert(NULL != ipv4p->sk);
                pcb = &((socket_t *)ipv4p->sk)->pcb.ipv4;
                if (NULL == pcb->cb.recv) {
                    /*
                        once a socket is bound to a specific ipv4 address without setting
                        callback function, all packets on that ipv4 address will be simply
                        bypassed.
                    */
                    goto DONE;
                }

                /*
                    for ip raw socket, pass whole ip header with payload to registered
                    recv function
                */
                pcb->cb.recv(pcb->cb.data,
                    (const unsigned char *)n_ipv4h, PBUF_GET_PAYLOAD_LEN(pbuf));

                goto DONE;
            }

#ifdef LUNE_DEBUG
            lune_assert(LUNE_SOCKET_IP == SOCKET_GET_TYPE(ipv4p->sk));
#endif
            /* ipv4 datagram socket */
            ip_socket_flag = 1;
        }
    }

    hdr_len = IPV4_GET_HDR_LEN(&h_ipv4h.hdr);
    (void)pbuf_move_up(pbuf, hdr_len);
    if (h_ipv4h.hdr.total_len < (PBUF_GET_PAYLOAD_LEN(pbuf) + hdr_len)) {
        /* trim trailing of mac layer */
        pbuf_update_payload_len(pbuf, h_ipv4h.hdr.total_len - hdr_len);
    }

    if (IPV4_IS_FRAG(&h_ipv4h.hdr)) {
        /* ipv4 fragment */
        orig_pbuf = pbuf;
        err =  ipv4_defrag(orig_pbuf, &pbuf, &h_ipv4h.hdr);
        if (err < 0) {
            lune_log(LUNE_INFO, "failed to defragment ipv4 packet: %s", ERR_GET_ERR_STR(err));
            return err;
        } else if (IPV4_DEFRAG_INCOMPLETE == err) {
            return 0;
        }

        lune_assert(IPV4_DEFRAG_COMPLETE == err);

        defrag_flag = 1;
    }

    if (ip_socket_flag) {
        /* ipv4 datagram socket */
        ip_pcb_t *pcb;

        lune_assert(NULL != ipv4p->sk);
        pcb = &((socket_t *)ipv4p->sk)->pcb.ip;
        if (NULL == pcb->cb.recv) {
            /*
                once a socket is bound to a specific ipv4 address without setting
                callback function, all packets on that ipv4 address will be simply
                bypassed.
            */
            goto DONE;
        }

        /*
            for ip datagram socket, pass payload with proto field to registered recv
            function
        */
        pcb->cb.recv(pcb->cb.data,
            (const unsigned char *)PBUF_GET_PAYLOAD(pbuf),
            PBUF_GET_PAYLOAD_LEN(pbuf),
            h_ipv4h.hdr.proto);

        goto DONE;
    }

    switch (h_ipv4h.hdr.proto) {
    case LUNE_IP_PROTO_TCP:
        err = tcp_input(ipv4p, &h_ipv4h.hdr, pbuf);
        break;
    case LUNE_IP_PROTO_UDP:
        if (multicast_flag) {
            if (NULL == (igp = igmp_find_group(h_ipv4h.hdr.dst_addr))) {
                break;
            }

            err = udp_input_multicast(igp, &h_ipv4h.hdr, pbuf);
        } else {
            err = udp_input_unicast(ipv4p, &h_ipv4h.hdr, pbuf);
        }
        break;
    case LUNE_IP_PROTO_ICMPV4:
        err = icmpv4_input(ipv4p, (void *)&h_ipv4h.hdr, pbuf);
        break;
    case LUNE_IP_PROTO_GRE:
        /* gre protocol not supported yet */
        break;
    case LUNE_IP_PROTO_IGMP:
        if (likely(multicast_flag)) {
            if (NULL == (igp = igmp_find_group(h_ipv4h.hdr.dst_addr))) {
                break;
            }

            err = igmp_input(igp, &h_ipv4h.hdr, pbuf);
        }
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

static inline unsigned short ipv4_get_frag_pkt_max_len(mac_t *macp)
{
    return ((mac_get_mtu(macp) - LUNE_IPV4_HDR_LEN) & (~0x07));
}

static inline void ipv4_build_hdr(lune_ipv4_hdr_t *ipv4h,
    lune_ipv4_addr_t src_addr,
    lune_ipv4_addr_t dst_addr,
    unsigned char proto,
    unsigned short pkt_id,
    unsigned short total_len,
    unsigned short offset,
    unsigned char tos,
    unsigned char ttl,
    unsigned char opt_len,
    unsigned int hw_csum_flag)
{
    ipv4h->ver_len = 0x40 + ((LUNE_IPV4_HDR_LEN + opt_len) >> 2);
    ipv4h->tos = tos;
    ipv4h->total_len = total_len + LUNE_IPV4_HDR_LEN + opt_len;
    ipv4h->id = pkt_id;
    ipv4h->offset = offset;
    ipv4h->ttl = ttl;
    ipv4h->proto = proto;
    ipv4h->src_addr = lune_htonl(src_addr);
    ipv4h->dst_addr = lune_htonl(dst_addr);
    ipv4h->total_len = lune_htons(ipv4h->total_len);
    ipv4h->id = lune_htons(ipv4h->id);
    ipv4h->offset = lune_htons(ipv4h->offset);
    ipv4h->csum = 0;
    if (!hw_csum_flag) {
        ipv4h->csum = csum_fold(csum_partial((unsigned char *)ipv4h, LUNE_IPV4_HDR_LEN + opt_len, 0));
    }
}

static inline int ipv4_output_done(ip_t *ipv4p, pbuf_t *pbuf, lune_ipv4_addr_t dst_addr)
{
    int err;
    unsigned long long bytes;

    switch (ipv4p->sub_type) {
    case LUNE_ID_MAC:
    {
        lune_mac_addr_t dst_mac;
        int ret;
        mac_t *macp = (mac_t *)ipv4p->sub_entry;

        bytes = PBUF_GET_PAYLOAD_LEN(pbuf) + PBUF_GET_HDR_LEN(pbuf);
        if (IPV4_IS_BROADCAST_IP(dst_addr)) {
            /* broadcast */
            if (unlikely(0 != (err = mac_output(macp,
                g_broadcast_mac, ETH_TYPE_IPV4_N, pbuf)))) {
                return err;
            }

            ipv4p->stats.pkt_out++;
            ipv4p->stats.byte_out += bytes;
            return 0;
        } else if (IPV4_IS_MULTICAST_IP(dst_addr)) {
            /* multicast */
            MAC_GET_IPV4_MC_MAC(dst_addr, dst_mac);
            if (unlikely(0 != (err = mac_output(macp,
                dst_mac, ETH_TYPE_IPV4_N, pbuf)))) {
                return err;
            }

            ipv4p->stats.pkt_out++;
            ipv4p->stats.byte_out += bytes;
            return 0;
        }

        ret = ipv4_route(macp, dst_mac, ipv4p, dst_addr, pbuf);
        if (ret != 0) {
            return ((ret > 0) ? 0 : ret);
        }

        if (unlikely(0 != (err = mac_output(macp,
            dst_mac, ETH_TYPE_IPV4_N, pbuf)))) {
            return err;
        }

        ipv4p->stats.pkt_out++;
        ipv4p->stats.byte_out += bytes;
        return 0;
    }
    default:
        return ERR_SET_ERR(LUNE_ERR_NOT_SUPPORTED);
    }
}

int ipv4_output(ip_t *ipv4p, lune_ipv4_addr_t dst_addr, unsigned char proto, pbuf_t *pbuf)
{
    unsigned short left_len, max_len = 0;
    unsigned short offset, t;
    lune_ipv4_hdr_t *ipv4h;
    unsigned short pkt_id;
    int err;
    unsigned char opt_len = 0; /* no option by default */
    unsigned short hdr_len = LUNE_IPV4_HDR_LEN + opt_len;
    unsigned short total_payload_len;

    ipv4h = (lune_ipv4_hdr_t *)pbuf_move_down(pbuf, hdr_len);
    pbuf->l3_len = hdr_len;
    PBUF_SET_L3_IPV4(pbuf);

#ifdef LUNE_DEBUG
    lune_assert(LUNE_ID_MAC == ipv4p->sub_type);
#endif

    total_payload_len = PBUF_GET_PAYLOAD_LEN(pbuf);
    if ((total_payload_len + hdr_len) > mac_get_mtu(ipv4p->sub_entry)) {
        max_len = ipv4_get_frag_pkt_max_len(ipv4p->sub_entry);
        t = LUNE_IPV4_FLAG_MF;
        left_len = total_payload_len - max_len;
        pbuf_truncate_pbuf(pbuf, max_len);
    } else {
        t = LUNE_IPV4_FLAG_DF;
        left_len = 0;
    }

    pkt_id = ipv4p->ipv4.pkt_id++;
    ipv4_build_hdr(ipv4h, ipv4p->ipv4.ip, dst_addr, proto, pkt_id, total_payload_len - left_len,
        t, IPV4_DEFAULT_TOS, IPV4_DEFAULT_TTL, opt_len, IP_IS_HW_TX_IP_CSUM(ipv4p));
    if (0 != (err = ipv4_output_done(ipv4p, pbuf, dst_addr))) {
        return err;
    }

    /*
        fragmentation, just notice that pbuf payload will be modified as part of it overlaps
        with header of fragmented ipv4 packets
    */
    offset = 0;
    while (left_len > max_len) {
        pbuf_rebase_pbuf(pbuf, left_len);
        (void)pbuf_move_down(pbuf, hdr_len);
        pbuf->l3_len = hdr_len;
        PBUF_SET_L3_IPV4(pbuf);
        ipv4h = (lune_ipv4_hdr_t *)PBUF_GET_HDR(pbuf);

        offset += max_len;
        pbuf_truncate_pbuf(pbuf, max_len);
        t = ((offset / 8) & LUNE_IPV4_FRAG_OFFSET) | LUNE_IPV4_FLAG_MF;

        ipv4_build_hdr(ipv4h, ipv4p->ipv4.ip, dst_addr, proto, pkt_id, max_len,
            t, IPV4_DEFAULT_TOS, IPV4_DEFAULT_TTL, opt_len, IP_IS_HW_TX_IP_CSUM(ipv4p));
        if (0 != (err = ipv4_output_done(ipv4p, pbuf, dst_addr))) {
            return err;
        }

        left_len -= max_len;
    }

    if (left_len > 0) {
        pbuf_rebase_pbuf(pbuf, left_len);
        (void)pbuf_move_down(pbuf, hdr_len);
        pbuf->l3_len = hdr_len;
        PBUF_SET_L3_IPV4(pbuf);
        ipv4h = (lune_ipv4_hdr_t *)PBUF_GET_HDR(pbuf);

        offset += max_len;
        t = (offset / 8) & LUNE_IPV4_FRAG_OFFSET;

        ipv4_build_hdr(ipv4h, ipv4p->ipv4.ip, dst_addr, proto, pkt_id, left_len,
            t, IPV4_DEFAULT_TOS, IPV4_DEFAULT_TTL, opt_len, IP_IS_HW_TX_IP_CSUM(ipv4p));
        return ipv4_output_done(ipv4p, pbuf, dst_addr);
    }

    return 0;
}

int ipv4_output_nofrag(ip_t *ipv4p, lune_ipv4_addr_t dst_addr, unsigned char proto, pbuf_t *pbuf)
{
    lune_ipv4_hdr_t *ipv4h;
    unsigned short pkt_id;
    unsigned char opt_len = 0;  /* no option by default */
    unsigned short hdr_len = LUNE_IPV4_HDR_LEN + opt_len;

    ipv4h = (lune_ipv4_hdr_t *)pbuf_move_down(pbuf, hdr_len);

    pbuf->l3_len = hdr_len;
    PBUF_SET_L3_IPV4(pbuf);

#ifdef LUNE_DEBUG
    lune_assert(LUNE_ID_MAC == ipv4p->sub_type);
    lune_assert((PBUF_GET_PAYLOAD_LEN(pbuf) + hdr_len) <= mac_get_mtu(ipv4p->sub_entry));
#endif

    pkt_id = ipv4p->ipv4.pkt_id++;
    ipv4_build_hdr(ipv4h, ipv4p->ipv4.ip, dst_addr, proto, pkt_id, PBUF_GET_PAYLOAD_LEN(pbuf),
        LUNE_IPV4_FLAG_DF, IPV4_DEFAULT_TOS, IPV4_DEFAULT_TTL, opt_len, IP_IS_HW_TX_IP_CSUM(ipv4p));
    return ipv4_output_done(ipv4p, pbuf, dst_addr);
}

unsigned int lune_add_ipv4(lune_ipv4_addr_t ipv4, lune_ipv4_addr_t mask,
    lune_ipv4_addr_t gw, lune_id_type_en sub_type, unsigned int sub_id)
{
    void *sub_entry;

    SCHED_CHECK_POINT();

    if (LUNE_INVALID_ID == sub_id
        || IPV4_IS_BROADCAST_IP(ipv4)
        || IPV4_IS_MULTICAST_IP(ipv4)) {
        ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        return LUNE_INVALID_ID;
    }

    if (LUNE_ID_MAC != sub_type) {
        ERR_SET_ERR(LUNE_ERR_NOT_SUPPORTED);
        return LUNE_INVALID_ID;
    }

    if (!IPV4_IS_VALID_MASK(mask)) {
        ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        return LUNE_INVALID_ID;
    }

    if (NULL == (sub_entry = id_get_entry(sub_type, sub_id))) {
        ERR_SET_ERR(LUNE_ERR_ID_NOT_FOUND);
        return LUNE_INVALID_ID;
    }

    return ipv4_add_ipv4(ipv4, mask, gw, sub_type, sub_entry);
}

int lune_del_ipv4(unsigned int id)
{
    ip_t *ipv4p;

    SCHED_CHECK_POINT();

    if (unlikely(LUNE_INVALID_ID == id)) {
        return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
    }

    if (NULL == (ipv4p = idtable_find(id, g_ip_idtable))) {
        return ERR_SET_ERR(LUNE_ERR_ID_NOT_FOUND);
    }

    if (unlikely(IP_IS_IPV6(ipv4p))) {
        return ERR_SET_ERR(LUNE_ERR_IP_TYPE_MISMATCH);
    }

    if (IP_IS_SOCKET(ipv4p)) {
        return ERR_SET_ERR(LUNE_ERR_NOT_CLOSED);
    }

    return ipv4_del_ipv4(ipv4p);
}

int lune_get_ipv4(lune_ipv4_addr_t ipv4,
    lune_id_type_en sub_type, unsigned int sub_id, unsigned int *ip_id)
{
    ip_t *ipv4p;
    void *sub_entry;
    void *ifp;

    SCHED_CHECK_POINT();

    if (NULL == ip_id) {
        return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
    }

    if (LUNE_INVALID_ID == sub_id
        || IPV4_IS_BROADCAST_IP(ipv4)
        || IPV4_IS_MULTICAST_IP(ipv4)) {
        *ip_id = LUNE_INVALID_ID;
        return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
    }

    if (LUNE_ID_MAC != sub_type) {
        *ip_id = LUNE_INVALID_ID;
        return ERR_SET_ERR(LUNE_ERR_NOT_SUPPORTED);
    }

    if (NULL == (sub_entry = id_get_entry(sub_type, sub_id))) {
        *ip_id = LUNE_INVALID_ID;
        return ERR_SET_ERR(LUNE_ERR_ID_NOT_FOUND);
    }

    if (LUNE_ID_MAC == sub_type
        && LUNE_ID_NET_IF == MAC_GET_SUB_TYPE(sub_entry)) {
        ifp = MAC_GET_SUB_ENTRY(sub_entry);
    } else {
        ifp = NULL;
    }

    if (NULL == (ipv4p = ip_get_ip_by_addr((void *)&ipv4,
        0, sub_type, sub_entry, ifp))) {
        *ip_id = LUNE_INVALID_ID;
        /* ERR_SET_ERR() unneeded */
        return -LUNE_ERR_NOT_EXIST;
    }

    *ip_id = ipv4p->id;
    return 0;
}

char *lune_ipv4_to_str(const lune_ipv4_addr_t addr, char *buf, unsigned int len)
{
    if (NULL == buf || len < LUNE_IPV4_MAX_ADDR_STR_LEN) {
        ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        return NULL;
    }

    sprintf(buf, "%d.%d.%d.%d",
        (addr & 0xff000000) >> 24, (addr & 0x00ff0000) >> 16, (addr & 0x0000ff00) >> 8, (addr & 0x000000ff));

    return buf;
}

static unsigned int s_ipv4_pow10[] = {
    1,
    10,
    100
};

int lune_str_to_ipv4(const char *str, lune_ipv4_addr_t *addr)
{
    unsigned int len, t;
    int i, j;

    if (NULL == str || NULL == addr) {
        return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
    }

    len = strlen(str);
    if (len > LUNE_IPV4_MAX_ADDR_STR_LEN
        || !LUNE_IS_DEC_CHAR(str[0])
        || !LUNE_IS_DEC_CHAR(str[len - 1])) {
        return ERR_SET_ERR(LUNE_ERR_MALFORMED_ARG);
    }

    i = j = t = 0;
    t = 0;
    while (len > 0) {
        len--;
        if (j > 3) {
            return ERR_SET_ERR(LUNE_ERR_MALFORMED_ARG);
        }

        if (str[len] == '.') {
            if (t >= 256) {
                return ERR_SET_ERR(LUNE_ERR_MALFORMED_ARG);
            }
            ((unsigned char *)addr)[j++] = (unsigned char)t;
            i = t = 0;
            continue;
        }

        if (!LUNE_IS_DEC_CHAR(str[len])) {
            return ERR_SET_ERR(LUNE_ERR_MALFORMED_ARG);
        }

        if (i > 2) {
            return ERR_SET_ERR(LUNE_ERR_MALFORMED_ARG);
        }

        t += (str[len] - '0') * s_ipv4_pow10[i++];
    }

    if (j != 3 || t >= 256) {
        return ERR_SET_ERR(LUNE_ERR_MALFORMED_ARG);
    }

    ((unsigned char *)addr)[j] = (unsigned char)t;

    return 0;
}

unsigned short ipv4_get_max_hdr_len(ip_t *ipv4p)
{
    unsigned short sub_entry_hdr_len;

    lune_assert(NULL != ipv4p);

    sub_entry_hdr_len = pbuf_get_max_hdr_len(ipv4p->sub_type, ipv4p->sub_entry);
    return IPV4_MAX_HDR_LEN + sub_entry_hdr_len;
}

int ipv4_join_group(ip_t *ipv4p, const lune_ipv4_join_group_arg_t *arg)
{
    return igmp_join_group(ipv4p, arg->group_addr, arg->igmp_ver);
}

int ipv4_leave_group(ip_t *ipv4p, lune_ipv4_addr_t group_addr)
{
    return igmp_leave_group(ipv4p, group_addr);
}

static int ipv4_socket_create(socket_t *sk)
{
    ipv4_pcb_t *pcb = &sk->pcb.ipv4;

    pcb->cb.recv = NULL;
    pcb->cb.data = NULL;
    pcb->ipv4p = NULL;

    return 0;
}

static int ipv4_socket_bind(socket_t *sk, const void *arg, unsigned int arg_len)
{
    ip_t *ipv4p;
    ipv4_pcb_t *pcb;

    if (arg_len != sizeof(unsigned int)) {
        return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
    }

    pcb = &sk->pcb.ipv4;
    if (NULL != pcb->ipv4p) {
        return ERR_SET_ERR(LUNE_ERR_ALREADY_BOUND);
    }

    if (NULL == (ipv4p = ip_get_ip_by_id(*(const unsigned int *)arg))) {
        return ERR_SET_ERR(LUNE_ERR_ID_NOT_FOUND);
    }

    if (IP_IS_SOCKET(ipv4p) || IP_L4_SOCKET_EXIST(ipv4p)) {
        return ERR_SET_ERR(LUNE_ERR_ALREADY_BOUND);
    }

    /*
        it is not necessary to ip_hold(ipv4p) because ipv4p cannot be deleted until socket is close
    */
    pcb->ipv4p = ipv4p;

    IP_SET_SOCKET(ipv4p);
    /*
        it is not necessary to socket_hold(sk) because ipv4p->sk exists only within the lifetime of socket
    */
    ipv4p->sk = sk;
    sk->rsvd_hdr_len = ipv4_get_max_hdr_len(ipv4p);

    return 0;
}

static int ipv4_socket_sendto(socket_t *sk, const unsigned char *buf, unsigned int len,
    const lune_ipv4_addr_t *dst_addr, unsigned int dst_addr_len,
    const lune_ipv4_sendto_arg_t *arg, unsigned int arg_len)
{
    ipv4_pcb_t *pcb;
    unsigned char lbuf[PBUF_MAX_RSVD_HDR_LEN + LUNE_NET_IF_MAX_MTU];
    pbuf_t pbuf;
    unsigned short hdr_len;
    lune_ipv4_hdr_t *ipv4h;

    if (unlikely(dst_addr_len != sizeof(lune_ipv4_addr_t)
        || NULL == arg || arg_len != sizeof(lune_ipv4_sendto_arg_t))) {
        return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
    }

    pcb = &sk->pcb.ipv4;

    lune_assert(LUNE_ID_MAC == pcb->ipv4p->sub_type);
    if (unlikely(LUNE_IPV4_HDR_LEN + arg->opt_len + len > ((mac_t *)(pcb->ipv4p->sub_entry))->mtu)) {
        return ERR_SET_ERR(LUNE_ERR_OVERSIZED_PKT);
    }

    if (unlikely(NULL == pcb->ipv4p)) {
        return ERR_SET_ERR(LUNE_ERR_NOT_BOUND);
    }

    pbuf_init_send_pbuf(&pbuf, lbuf, len, PBUF_MAX_RSVD_HDR_LEN, IP_IS_DPDK(pcb->ipv4p));
    if (likely(len > 0)) {
        memcpy(PBUF_GET_HDR(&pbuf), buf, len);
    }
    hdr_len = LUNE_IPV4_HDR_LEN + arg->opt_len;
    ipv4h = (lune_ipv4_hdr_t *)pbuf_move_down(&pbuf, hdr_len);
    pbuf.l3_len = hdr_len;
    PBUF_SET_L3_IPV4(&pbuf);

    ipv4_build_hdr(ipv4h, pcb->ipv4p->ipv4.ip, *dst_addr, arg->proto, arg->id, arg->total_len,
        arg->offset, arg->tos, arg->ttl, arg->opt_len, IP_IS_HW_TX_IP_CSUM(pcb->ipv4p));

    return ipv4_output_done(pcb->ipv4p, &pbuf, *dst_addr);
}

static int ipv4_socket_get_opt(socket_t *sk, lune_socket_opt_en opt, unsigned char *opt_val, unsigned int opt_len)
{
    ipv4_pcb_t *pcb = &sk->pcb.ipv4;

    switch (opt) {
    case LUNE_SOCKET_OPT_GET_SRC_IP_ID:
        if (unlikely(NULL == opt_val || opt_len != sizeof(unsigned int))) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        if (NULL == pcb->ipv4p) {
            return ERR_SET_ERR(LUNE_ERR_NOT_BOUND);
        }

        *(unsigned int *)opt_val = pcb->ipv4p->id;
        break;
    default:
        return ERR_SET_ERR(LUNE_ERR_OPT_NOT_FOUND);
    }

    return 0;
}

static int ipv4_socket_set_opt(socket_t *sk,
    lune_socket_opt_en opt, const unsigned char *opt_val, unsigned int opt_len)
{
    ipv4_pcb_t *pcb = &sk->pcb.ipv4;

    switch (opt) {
    case LUNE_SOCKET_OPT_SET_CALLBACK:
        if (NULL == opt_val
            || opt_len != sizeof(lune_ipv4_socket_callback_t)) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        pcb->cb.recv = ((const lune_ipv4_socket_callback_t *)opt_val)->recv;
        pcb->cb.data = ((const lune_ipv4_socket_callback_t *)opt_val)->data;
        break;
    default:
        return ERR_SET_ERR(LUNE_ERR_OPT_NOT_FOUND);
    }

    return 0;
}

static int ipv4_socket_close(socket_t *sk)
{
    ip_t *ipv4p;
    ipv4_pcb_t *pcb = &sk->pcb.ipv4;

    pcb->cb.recv = NULL;

    ipv4p = pcb->ipv4p;
    if (NULL != ipv4p) {
        IP_SET_NON_SOCK(ipv4p);
        ipv4p->sk = NULL;
        pcb->ipv4p = NULL;
    }

    return 0;
}

static unsigned short ipv4_socket_get_max_hdr_len(socket_t *sk)
{
    ip_t *ipv4p = sk->pcb.ipv4.ipv4p;

    lune_assert(LUNE_ID_MAC == ipv4p->sub_type);

    return ipv4_get_max_hdr_len(ipv4p);
}

socket_ops_t g_socket_ops_ipv4 = {
    .create = (socket_create_func_t)ipv4_socket_create,
    .bind = (socket_bind_func_t)ipv4_socket_bind,
    .connect = NULL,
    .listen = NULL,
    .send = NULL,
    .send_pkts = NULL,
    .sendto = (socket_sendto_func_t)ipv4_socket_sendto,
    .get_opt = (socket_get_opt_func_t)ipv4_socket_get_opt,
    .set_opt = (socket_set_opt_func_t)ipv4_socket_set_opt,
    .close = (socket_close_func_t)ipv4_socket_close,
    .hash = NULL,
    .compare = NULL,
    .get_max_hdr_len = (socket_get_max_hdr_len_func_t)ipv4_socket_get_max_hdr_len,
};

int ipv4_local_init(void)
{
    if (NULL == (s_ipv4_frag_htable = htable_create_table("ipv4 fragment hash table",
        (htable_hash_func_t)ipv4_frag_htable_hash,
        (htable_compare_func_t)ipv4_frag_htable_compare,
        (htable_free_func_t)ipv4_delete_defrag,
        offsetof(ipv4_defrag_t, node),
        IPV4_FRAG_HTABLE_SIZE,
        0))) {
        return ERR_GET_LAST_ERR();
    }

    return 0;
}

void ipv4_local_fini(void)
{
    lune_assert(!htable_delete_table(s_ipv4_frag_htable));
    s_ipv4_frag_htable = NULL;
}
