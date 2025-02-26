/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2024 Lune Reseau, Inc.
 */

#include "lune/assert.h"
#include "lune/id.h"
#include "lune/ip.h"
#include "lune/list.h"
#include "lune/mem.h"
#include "lune/net.h"
#include "lune/time.h"

#include "kernel/timer.h"
#include "lib/common.h"
#include "lib/csum.h"
#include "lib/htable.h"
#include "lib/idlist.h"
#include "lib/idtable.h"
#include "net/pbuf.h"
#include "net/socket.h"
#include "net/igmp.h"
#include "net/igmp.h"
#include "rt/core.h"

#ifdef LUNE_BIG_ENDIAN
#define IGMP_ALL_HOSTS_ADDR_N               (0xe0000001)
#define IGMP_ALL_ROUTERS_ADDR_N             (0xe0000002)
#else
#define IGMP_ALL_HOSTS_ADDR_N               (0x010000e0)
#define IGMP_ALL_ROUTERS_ADDR_N             (0x020000e0)
#endif
#define IGMP_ALL_HOSTS_ADDR_H               (0xe0000001)
#define IGMP_ALL_ROUTERS_ADDR_H             (0xe0000002)

#define IGMP_GROUP_HTABLE_SIZE_IN_BIT       (14)
#define IGMP_GROUP_HTABLE_SIZE              (1 << (IGMP_GROUP_HTABLE_SIZE_IN_BIT))
#define IGMP_GROUP_HTABLE_MASK              (IGMP_GROUP_HTABLE_SIZE - 1)

#define IGMP_HOST_GROUP_HTABLE_SIZE_IN_BIT  (15)
#define IGMP_HOST_GROUP_HTABLE_SIZE         (1 << (IGMP_HOST_GROUP_HTABLE_SIZE_IN_BIT))
#define IGMP_HOST_GROUP_HTABLE_MASK         (IGMP_HOST_GROUP_HTABLE_SIZE - 1)

#define IGMP_DEFAULT_MRT_TIME               (100)   /* 10s */
#define IGMP_DEFAULT_DELAY_REPORT_TIME      (LUNE_TIME_MILLISECOND * 100)

#define IGMP_MEMBER_QUERY                   0x11
#define IGMP_V1_MEMBER_REPORT               0x12
#define IGMP_V2_MEMBER_REPORT               0x16
#define IGMP_V3_MEMBER_REPORT               0x22
#define IGMP_LEAVE_GROUP                    0x17

#define IGMP_GET_MEMBER_REPORT_TYPE(ver)    s_igmp_member_report_type[ver]
static const unsigned char s_igmp_member_report_type[LUNE_IGMP_VERSION_MAX] = {
    IGMP_V1_MEMBER_REPORT,
    IGMP_V2_MEMBER_REPORT,
    IGMP_V3_MEMBER_REPORT,
};

static __thread void *s_igmp_group_htable = NULL;

static inline void igmp_build_hdr(lune_igmp_hdr_t *igmph,
    unsigned char type,
    unsigned char mrt,
    lune_ipv4_addr_t group_addr)
{
    igmph->type = type;
    igmph->mrt = mrt;
    igmph->group_addr = lune_htonl(group_addr);
    igmph->csum = 0;
    igmph->csum = csum_fold(csum_partial((const unsigned char *)igmph, LUNE_IGMP_HDR_LEN, 0));
}

static unsigned int igmp_host_group_htable_hash(igmp_host_group_t *ihgp)
{
    return (ihgp->ipv4p->ipv4.ip) & IGMP_HOST_GROUP_HTABLE_MASK;
}

static int igmp_host_group_htable_compare(igmp_host_group_t *ihgp1, igmp_host_group_t *ihgp2)
{
    return (!(ihgp1->ipv4p == ihgp2->ipv4p));
}

static void igmp_delete_host_group(igmp_host_group_t *ihgp)
{
    if (!CORE_IS_QUITTING()) {
        lune_assert(dlist_is_empty(&ihgp->igmp_socket_list));
        lune_assert(dlist_is_empty(&ihgp->udp_socket_list));
    } else {
        /*
            NOTICE:
            no need to deal with sockets that are still on the list as they
            are all freed. socket_local_fini() is called prior to igmp_local_fini()
        */
    }

    dlist_del(&ihgp->node2);
    ip_put(ihgp->ipv4p);
    lune_free(ihgp);
}

static inline int igmp_output(ip_t *ipv4p,
    lune_ipv4_addr_t group_addr,
    lune_ipv4_addr_t dst_addr,
    unsigned char type,
    unsigned char mrt,
    pbuf_t *pbuf)
{
    lune_igmp_hdr_t *igmph;
    lune_ip_addr_t addr;

    igmph = (lune_igmp_hdr_t *)pbuf_move_down(pbuf, LUNE_IGMP_HDR_LEN);
    igmp_build_hdr(igmph, type, mrt, group_addr);

    addr.is_ipv6 = 0;
    addr.ipv4 = dst_addr;
    return ip_output(ipv4p, (const lune_ip_addr_t *)&addr, LUNE_IP_PROTO_IGMP, pbuf);
}

static void igmp_delay_report_tmr_func(igmp_group_t *igp)
{
    igmp_host_group_t *ihgp;
    unsigned char lbuf[PBUF_MAX_RSVD_HDR_LEN + IP_MAX_PAYLOAD_BUF_SIZE];
    pbuf_t tx_pbuf;
    char group_ip_str[LUNE_IPV4_MAX_ADDR_STR_LEN];
    int err;

    lune_assert(!dlist_is_empty(&igp->host_group_list));

    ihgp = dlist_first(&igp->host_group_list, igmp_host_group_t, node2);
    pbuf_init_send_pbuf(&tx_pbuf, lbuf, 0, PBUF_MAX_RSVD_HDR_LEN, 0);
    if (0 != (err = igmp_output(ihgp->ipv4p, ihgp->igp->group_addr,
        ihgp->igp->group_addr, IGMP_GET_MEMBER_REPORT_TYPE(ihgp->ver), IGMP_DEFAULT_MRT_TIME, &tx_pbuf))) {
        lune_log(LUNE_INFO, "failed to send igmp delay report for multicast group %s: %s",
            lune_ipv4_to_str(igp->group_addr, group_ip_str, LUNE_IPV4_MAX_ADDR_STR_LEN),
            ERR_GET_ERR_STR(err));
    }
}

int igmp_join_group(ip_t *ipv4p, lune_ipv4_addr_t group_addr, lune_igmp_version_en ver)
{
    igmp_group_t *igp, ig;
    igmp_host_group_t *ihgp;
    int err;
    unsigned char lbuf[PBUF_MAX_RSVD_HDR_LEN + IP_MAX_PAYLOAD_BUF_SIZE];
    pbuf_t tx_pbuf;

    if (unlikely(!IPV4_IS_MULTICAST_IP(group_addr)
        || ver < LUNE_IGMP_VERSION_1
        || ver >= LUNE_IGMP_VERSION_MAX)) {
        return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
    }

    ig.group_addr = group_addr;
    if (NULL == (igp = htable_find((void *)&ig, s_igmp_group_htable))) {
        if (NULL == (igp = lune_malloc(sizeof(igmp_group_t)))) {
            err = ERR_GET_LAST_ERR();
            goto NEW_IG_ERR_1;
        }

        dlist_init_head(&igp->host_group_list);
        igp->group_addr = group_addr;
        igp->host_cnt = 1;
        igp->igmp_socket_cnt = 0;
        timer_init_timer(&igp->delay_report_tmr, LUNE_TIMER_ONCE,
            LUNE_TIMER_RES_HIGH, (lune_timer_func_t)igmp_delay_report_tmr_func, (void *)igp);

        if (NULL == (igp->host_group_htable = htable_create_table("igmp host group hash table",
            (htable_hash_func_t)igmp_host_group_htable_hash,
            (htable_compare_func_t)igmp_host_group_htable_compare,
            (htable_free_func_t)igmp_delete_host_group,
            offsetof(igmp_host_group_t, node),
            IGMP_HOST_GROUP_HTABLE_SIZE,
            1))) {
            err = ERR_GET_LAST_ERR();
            goto NEW_IG_ERR_2;
        }

        if (NULL == (ihgp = lune_malloc(sizeof(igmp_host_group_t)))) {
            err = ERR_GET_LAST_ERR();
            goto NEW_IG_ERR_3;
        }

        dlist_init_head(&ihgp->igmp_socket_list);
        dlist_init_head(&ihgp->udp_socket_list);
        ihgp->ipv4p = ipv4p;
        ip_hold(ipv4p);
        ihgp->igp = igp;
        ihgp->ver = ver;

        if (0 != (err = htable_insert((void *)ihgp, igp->host_group_htable, 1))) {
            goto NEW_IG_ERR_4;
        }

        dlist_add_tail(&ihgp->node2, &igp->host_group_list);

        if (0 != (err = htable_insert((void *)igp, s_igmp_group_htable, 1))) {
            goto NEW_IG_ERR_5;
        }

        pbuf_init_send_pbuf(&tx_pbuf, lbuf, 0, PBUF_MAX_RSVD_HDR_LEN, 0);
        if (0 != (err = igmp_output(ipv4p,
            group_addr, group_addr, IGMP_GET_MEMBER_REPORT_TYPE(ver), IGMP_DEFAULT_MRT_TIME, &tx_pbuf))) {
            goto NEW_IG_ERR_6;
        }

        return 0;

NEW_IG_ERR_6:
        lune_assert(!htable_remove((void *)igp, s_igmp_group_htable));

NEW_IG_ERR_5:
        dlist_del(&ihgp->node2);
        lune_assert(!htable_remove((void *)ihgp, igp->host_group_htable));

NEW_IG_ERR_4:
        ip_put(ipv4p);
        lune_free(ihgp);

NEW_IG_ERR_3:
        lune_assert(!htable_delete_table(igp->host_group_htable));

NEW_IG_ERR_2:
        lune_free(igp);

NEW_IG_ERR_1:
        return err;
    }

    if (NULL == (ihgp = lune_malloc(sizeof(igmp_host_group_t)))) {
        err = ERR_GET_LAST_ERR();
        goto NEW_IHG_ERR_1;
    }

    dlist_init_head(&ihgp->igmp_socket_list);
    dlist_init_head(&ihgp->udp_socket_list);
    ihgp->ipv4p = ipv4p;
    ip_hold(ipv4p);
    ihgp->igp = igp;
    ihgp->ver = ver;

    if (0 != (err = htable_insert((void *)ihgp, igp->host_group_htable, 0))) {
        goto NEW_IHG_ERR_2;
    }

    dlist_add_tail(&ihgp->node2, &igp->host_group_list);

    pbuf_init_send_pbuf(&tx_pbuf, lbuf, 0, PBUF_MAX_RSVD_HDR_LEN, 0);
    if (0 != (err = igmp_output(ipv4p,
        group_addr, group_addr, IGMP_GET_MEMBER_REPORT_TYPE(ver), IGMP_DEFAULT_MRT_TIME, &tx_pbuf))) {
        goto NEW_IHG_ERR_3;
    }

    igp->host_cnt++;

    return 0;

NEW_IHG_ERR_3:
    dlist_del(&ihgp->node2);
    lune_assert(!htable_remove((void *)ihgp, igp->host_group_htable));

NEW_IHG_ERR_2:
    ip_put(ipv4p);
    lune_free(ihgp);

NEW_IHG_ERR_1:
    return err;
}

int igmp_leave_group(ip_t *ipv4p, lune_ipv4_addr_t group_addr)
{
    igmp_group_t *igp, ig;
    igmp_host_group_t *ihgp, ihg;
    int err;
    unsigned char lbuf[PBUF_MAX_RSVD_HDR_LEN + IP_MAX_PAYLOAD_BUF_SIZE];
    pbuf_t tx_pbuf;

    ig.group_addr = group_addr;
    if (NULL == (igp = htable_find((void *)&ig, s_igmp_group_htable))) {
        return ERR_SET_ERR(LUNE_ERR_NOT_EXIST);
    }

    ihg.ipv4p = ipv4p;
    ihg.igp = igp;
    if (NULL == (ihgp = htable_find((void *)&ihg, igp->host_group_htable))) {
        return ERR_SET_ERR(LUNE_ERR_NOT_EXIST);
    }

    if (1 == igp->host_cnt) {
        /* the last to leave the multicast group */
        pbuf_init_send_pbuf(&tx_pbuf, lbuf, 0, PBUF_MAX_RSVD_HDR_LEN, 0);
        if (0 != (err = igmp_output(ipv4p,
            group_addr, IGMP_ALL_ROUTERS_ADDR_H, IGMP_LEAVE_GROUP, 0, &tx_pbuf))) {
            return err;
        }
    }

    igp->host_cnt--;

    {
        igmp_pcb_t *pcb, *pcb2;
        dlist_for_each_node_safe(pcb, pcb2, &ihgp->igmp_socket_list, node) {
            dlist_del_init(&pcb->node);
            igp->igmp_socket_cnt--;
        }
    }

    {
        udp_pcb_t *pcb, *pcb2;
        dlist_for_each_node_safe(pcb, pcb2, &ihgp->udp_socket_list, node) {
            dlist_del_init(&pcb->node);
        }
    }

    dlist_del(&ihgp->node2);
    lune_assert(!htable_remove((void *)ihgp, igp->host_group_htable));
    ip_put(ipv4p);
    lune_free(ihgp);

    if (0 == igp->host_cnt) {
        lune_assert(0 == igp->igmp_socket_cnt);

        if (LUNE_TIMER_IS_ADDED(igp->delay_report_tmr)) {
            timer_del_timer(&igp->delay_report_tmr);
        }

        lune_assert(!htable_remove((void *)igp, s_igmp_group_htable));
        lune_assert(!htable_delete_table(igp->host_group_htable));
        lune_free(igp);
    }

    return 0;
}

igmp_group_t *igmp_find_group(lune_ipv4_addr_t group_addr)
{
    igmp_group_t ig;

    ig.group_addr = group_addr;
    return htable_find((void *)&ig, s_igmp_group_htable);
}

int igmp_input(igmp_group_t *igp, lune_ipv4_hdr_t *ipv4h, pbuf_t *pbuf)
{
    igmp_host_group_t *ihgp;
    lune_igmp_hdr_t *igmph = (lune_igmp_hdr_t *)PBUF_GET_PAYLOAD(pbuf);
    socket_t *sk;

    lune_ntohl(igmph->group_addr);

    if (igp->igmp_socket_cnt > 0) {
        /*
            NOTICE:
            igmp packets will be intercepted by igmp socket(s) if any
        */
        igmp_group_for_each_host_group(ihgp, igp) {
            igmp_pcb_t *pcb;
            dlist_for_each_node(pcb, &ihgp->igmp_socket_list, node) {
                if (likely(NULL != pcb->cb.recvfrom)) {
                    sk = lune_container_of(pcb, socket_t, pcb.igmp);
                    SOCKET_PUSH_CB_SK(sk);
                    pcb->cb.recvfrom(pcb->cb.data, ipv4h->src_addr,
                        (const unsigned char *)igmph, PBUF_GET_PAYLOAD_LEN(pbuf));
                    SOCKET_POP_CB_SK();
                }
            }
        }

        return 0;
    }

    (void)pbuf_move_up(pbuf, LUNE_IGMP_HDR_LEN);

    switch (igmph->type) {
    case IGMP_MEMBER_QUERY:
        if (IGMP_ALL_HOSTS_ADDR_H == ipv4h->dst_addr) {
            /* TODO: general query */
        } else {
            /* specific query */
            if (NULL == (igp = igmp_find_group(igmph->group_addr))) {
                return 0;
            }

            /* send report from one member */
            if (!LUNE_TIMER_IS_ADDED(igp->delay_report_tmr)) {
                timer_add_timer(&igp->delay_report_tmr, IGMP_DEFAULT_DELAY_REPORT_TIME);
            }
        }

        return 0;
    case IGMP_V1_MEMBER_REPORT:
        break;
    case IGMP_V2_MEMBER_REPORT:
        break;
    case IGMP_V3_MEMBER_REPORT:
        break;
    default:
        return 0;
    }

    return 0;
}

static unsigned int igmp_group_htable_hash(igmp_group_t *igp)
{
    return (igp->group_addr) & IGMP_GROUP_HTABLE_MASK;
}

static int igmp_group_htable_compare(igmp_group_t *igp1, igmp_group_t *igp2)
{
    return (!(igp1->group_addr == igp2->group_addr));
}

static void igmp_delete_group(igmp_group_t *igp)
{
    if (LUNE_TIMER_IS_ADDED(igp->delay_report_tmr)) {
        timer_del_timer(&igp->delay_report_tmr);
    }

    lune_assert(!htable_delete_table(igp->host_group_htable));
    lune_free(igp);
}

static unsigned short igmp_socket_get_max_hdr_len(socket_t *sk)
{
    igmp_pcb_t *pcb = &sk->pcb.igmp;
    unsigned short sub_entry_hdr_len;

    lune_assert(NULL != pcb->ipv4p);

    sub_entry_hdr_len = pbuf_get_max_hdr_len(
        IP_IS_IPV6(pcb->ipv4p) ? LUNE_ID_IPV6 : LUNE_ID_IPV4, pcb->ipv4p);
    return LUNE_IGMP_HDR_LEN + sub_entry_hdr_len;
}

static int igmp_socket_create(socket_t *sk)
{
    igmp_pcb_t *pcb = &sk->pcb.igmp;

    pcb->cb.recvfrom = NULL;
    pcb->cb.data = NULL;
    pcb->ipv4p = NULL;
    pcb->group_addr = 0;

    return 0;
}

static int igmp_socket_bind(socket_t *sk, const void *arg, unsigned int arg_len)
{
    ip_t *ipp;
    igmp_pcb_t *pcb;

    if (unlikely(arg_len != sizeof(unsigned int))) {
        return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
    }

    pcb = &sk->pcb.igmp;
    if (unlikely(NULL != pcb->ipv4p)) {
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

    if (unlikely(IP_IS_IPV6(ipp))) {
        /* igmp socket only works for ipv4 */
        return ERR_SET_ERR(LUNE_ERR_NOT_SUPPORTED);
    }

    pcb->ipv4p = ipp;

    ip_hold(ipp);
    IP_SET_L4_SOCKET(ipp);

    sk->rsvd_hdr_len = igmp_socket_get_max_hdr_len(sk);

    return 0;
}

static int igmp_socket_sendto(socket_t *sk, const unsigned char *buf, unsigned int len,
    const void *dst_addr, unsigned int dst_addr_len, const lune_igmp_sendto_arg_t *arg, unsigned int arg_len)
{
    igmp_pcb_t *pcb;
    unsigned char lbuf[PBUF_MAX_RSVD_HDR_LEN + IP_MAX_PAYLOAD_BUF_SIZE];
    pbuf_t tx_pbuf;

    if (unlikely(dst_addr_len != sizeof(lune_ipv4_addr_t)
        || NULL == arg || arg_len != sizeof(lune_igmp_sendto_arg_t))) {
        return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
    }

    pcb = &sk->pcb.igmp;

    if (unlikely(len > LUNE_IGMP_MAX_PAYLOAD_LEN)) {
        return ERR_SET_ERR(LUNE_ERR_OVERSIZED_PKT);
    }

    if (unlikely(NULL == pcb->ipv4p)) {
        return ERR_SET_ERR(LUNE_ERR_NOT_BOUND);
    }

    pbuf_init_send_pbuf(&tx_pbuf, lbuf, len, PBUF_MAX_RSVD_HDR_LEN, 0);
    if (unlikely(len > 0)) {
        memcpy(PBUF_GET_HDR(&tx_pbuf), buf, len);
    }

    return igmp_output(pcb->ipv4p, *((const lune_ipv4_addr_t *)dst_addr),
        arg->group_addr, arg->type, arg->mrt, &tx_pbuf);
}

static int igmp_socket_get_opt(socket_t *sk, lune_socket_opt_en opt, unsigned char *opt_val, unsigned int opt_len)
{
    igmp_pcb_t *pcb = &sk->pcb.igmp;

    switch (opt) {
    case LUNE_SOCKET_OPT_GET_SRC_IP_ID:
        if (unlikely(NULL == opt_val || opt_len != sizeof(unsigned int))) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        if (NULL == pcb->ipv4p) {
            return ERR_SET_ERR(LUNE_ERR_NOT_BOUND);
        }

        *(unsigned int *)opt_val = IP_GET_ID(pcb->ipv4p);
        break;
    default:
        return ERR_SET_ERR(LUNE_ERR_OPT_NOT_FOUND);
    }

    return 0;
}

static int igmp_socket_join_host_group(igmp_pcb_t *pcb, lune_ipv4_addr_t group_addr)
{
    igmp_group_t *igp;
    igmp_host_group_t *ihgp, ihg;

    if (NULL == (igp = igmp_find_group(group_addr))) {
        return ERR_SET_ERR(LUNE_ERR_NOT_EXIST);
    }

    ihg.ipv4p = pcb->ipv4p;
    ihg.igp = igp;
    if (NULL == (ihgp = htable_find((void *)&ihg, igp->host_group_htable))) {
        return ERR_SET_ERR(LUNE_ERR_NOT_EXIST);
    }

    igp->igmp_socket_cnt++;

    dlist_add_tail(&pcb->node, &ihgp->igmp_socket_list);
    return 0;
}

static void igmp_socket_leave_host_group(igmp_pcb_t *pcb)
{
    igmp_group_t *igp;
    char group_ip_str[LUNE_IPV4_MAX_ADDR_STR_LEN];
    char host_ip_str[LUNE_IPV4_MAX_ADDR_STR_LEN];

    if (NULL == (igp = igmp_find_group(pcb->group_addr))) {
        return;
    }

    if (likely(dlist_node_is_added(&pcb->node))) {
        dlist_del_init(&pcb->node);
        igp->igmp_socket_cnt--;
    } else {
        lune_log(LUNE_DBG, "host group <%s, %s> has been deleted while socket %d attempting to leave it",
            lune_ipv4_to_str(pcb->ipv4p->ipv4.ip, host_ip_str, LUNE_IPV4_MAX_ADDR_STR_LEN),
            lune_ipv4_to_str(igp->group_addr, group_ip_str, LUNE_IPV4_MAX_ADDR_STR_LEN));
    }
}

static int igmp_socket_set_opt(socket_t *sk,
    lune_socket_opt_en opt, const unsigned char *opt_val, unsigned int opt_len)
{
    igmp_pcb_t *pcb = &sk->pcb.igmp;
    int err;

    switch (opt) {
    case LUNE_SOCKET_OPT_SET_CALLBACK:
        if (NULL == opt_val
            || opt_len != sizeof(lune_igmp_socket_callback_t)) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        pcb->cb.recvfrom = ((const lune_igmp_socket_callback_t *)opt_val)->recvfrom;
        pcb->cb.data = ((const lune_igmp_socket_callback_t *)opt_val)->data;
        break;
    case LUNE_SOCKET_OPT_ADD_MEMBERSHIP:
        if (unlikely(NULL == opt_val
            || opt_len != sizeof(lune_ipv4_addr_t))) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        if (unlikely(NULL == pcb->ipv4p)) {
            return ERR_SET_ERR(LUNE_ERR_NOT_BOUND);
        }

        if (unlikely(pcb->group_addr != 0)) {
            return ERR_SET_ERR(LUNE_ERR_ALREADY_SET);
        }

        if (unlikely(!IPV4_IS_MULTICAST_IP(*(const lune_ipv4_addr_t *)opt_val))) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        if (0 != (err = igmp_socket_join_host_group(pcb, *(const lune_ipv4_addr_t *)opt_val))) {
            return err;
        }

        pcb->group_addr = *(const lune_ipv4_addr_t *)opt_val;
        break;
    case LUNE_SOCKET_OPT_DROP_MEMBERSHIP:
        if (unlikely(NULL != opt_val
            || 0 != opt_len)) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        if (unlikely(NULL == pcb->ipv4p)) {
            return ERR_SET_ERR(LUNE_ERR_NOT_BOUND);
        }

        if (unlikely(0 == pcb->group_addr)) {
            return ERR_SET_ERR(LUNE_ERR_NOT_SET);
        }

        igmp_socket_leave_host_group(pcb);
        pcb->group_addr = 0;
        break;
    default:
        return ERR_SET_ERR(LUNE_ERR_OPT_NOT_FOUND);
    }

    return 0;
}

static int igmp_socket_close(socket_t *sk)
{
    igmp_pcb_t *pcb = &sk->pcb.igmp;

    lune_assert(!socket_is_added(sk));

    pcb->cb.recvfrom = NULL;

    if (NULL != pcb->ipv4p) {
        ip_put(pcb->ipv4p);
        pcb->ipv4p = NULL;
    }

    return 0;
}

socket_ops_t g_socket_ops_igmp = {
    .create = (socket_create_func_t)igmp_socket_create,
    .bind = (socket_bind_func_t)igmp_socket_bind,
    .connect = NULL,
    .listen = NULL,
    .send = NULL,
    .send_pkts = NULL,
    .sendto = (socket_sendto_func_t)igmp_socket_sendto,
    .get_opt = (socket_get_opt_func_t)igmp_socket_get_opt,
    .set_opt = (socket_set_opt_func_t)igmp_socket_set_opt,
    .close = (socket_close_func_t)igmp_socket_close,
    .hash = NULL,
    .compare = NULL,
    .get_max_hdr_len = (socket_get_max_hdr_len_func_t)igmp_socket_get_max_hdr_len,
};

int igmp_local_init(void)
{
    if (NULL == (s_igmp_group_htable = htable_create_table("igmp group hash table",
        (htable_hash_func_t)igmp_group_htable_hash,
        (htable_compare_func_t)igmp_group_htable_compare,
        (htable_free_func_t)igmp_delete_group,
        offsetof(igmp_group_t, node),
        IGMP_GROUP_HTABLE_SIZE,
        0))) {
        return ERR_GET_LAST_ERR();
    }

    return 0;
}

void igmp_local_fini(void)
{
    lune_assert(!htable_delete_table(s_igmp_group_htable));
    s_igmp_group_htable = NULL;
}
