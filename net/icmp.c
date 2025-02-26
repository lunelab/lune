/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2024 Lune Reseau, Inc.
 */

#include "lune/assert.h"
#include "lune/id.h"
#include "lune/ip.h"
#include "lune/list.h"
#include "lune/net.h"

#include "lib/csum.h"
#include "lib/common.h"
#include "lib/htable.h"
#include "lib/idlist.h"
#include "lib/idtable.h"
#include "net/icmp.h"
#include "net/ip.h"
#include "net/nb.h"
#include "net/pbuf.h"
#include "net/socket.h"

#define ICMPV6_IS_NB_MSG(icmph)     \
    (LUNE_ICMPV6_NB_SOLICIT == (icmph)->type || LUNE_ICMPV6_NB_ADVERT == (icmph)->type)

static inline unsigned short icmpv6_calc_csum(const lune_icmp_hdr_t *icmph,
    ip_t *ipv6p,
    const lune_ipv6_addr_t *dst_ip,
    unsigned short icmp_len)
{
    unsigned int sum;

    sum = csum_partial((const unsigned char *)icmph, icmp_len, 0);

    lune_ipv6_psd_hdr_t ipv6h;
    LUNE_IPV6_CPY(ipv6h.src_addr.addr, ipv6p->ipv6.ip.addr);
    LUNE_IPV6_CPY(ipv6h.dst_addr.addr, dst_ip);
    ipv6h.len = lune_htons(icmp_len);
    *(unsigned int *)ipv6h.zeros = 0;
    ipv6h.proto = LUNE_IP_PROTO_ICMPV6;
    sum = csum_partial((unsigned char *)&ipv6h, sizeof(lune_ipv6_psd_hdr_t), sum);

    return csum_fold(sum);
}

static inline void icmpv4_build_hdr(lune_icmp_hdr_t *icmph,
    unsigned char type,
    unsigned char code,
    unsigned int data,
    unsigned int data_len)
{
    icmph->type = type;
    icmph->code = code;
    icmph->data = data;
    icmph->csum = 0;
    icmph->csum = csum_fold(csum_partial((const unsigned char *)icmph, LUNE_ICMP_HDR_LEN + data_len, 0));
}

static inline void icmpv6_build_hdr(lune_icmp_hdr_t *icmph,
    unsigned char type,
    unsigned char code,
    unsigned int data,
    unsigned int data_len,
    ip_t *ipv6p,
    const lune_ipv6_addr_t *dst_ip)
{
    icmph->type = type;
    icmph->code = code;
    icmph->data = data;
    icmph->csum = 0;
    icmph->csum = icmpv6_calc_csum(icmph, ipv6p, dst_ip, LUNE_ICMP_HDR_LEN + data_len);
}

static inline int icmp_output(ip_t *ipp,
    const lune_ip_addr_t *dst_ip,
    unsigned char type,
    unsigned char code,
    unsigned int data,
    pbuf_t *pbuf)
{
    lune_icmp_hdr_t *icmph = (lune_icmp_hdr_t *)pbuf_move_down(pbuf, LUNE_ICMP_HDR_LEN);

    if (IP_IS_IPV6(ipp)) {
        icmpv6_build_hdr(icmph, type, code, data, PBUF_GET_PAYLOAD_LEN(pbuf), ipp, &dst_ip->ipv6);
        return ip_output(ipp, dst_ip, LUNE_IP_PROTO_ICMPV6, pbuf);
    } else {
        icmpv4_build_hdr(icmph, type, code, data, PBUF_GET_PAYLOAD_LEN(pbuf));
        return ip_output(ipp, dst_ip, LUNE_IP_PROTO_ICMPV4, pbuf);
    }
}

int icmpv6_send_nb_solicit(ip_t *ipv6p, const lune_ipv6_addr_t *dst_addr)
{
    unsigned char lbuf[PBUF_MAX_RSVD_HDR_LEN], *buf;
    pbuf_t pbuf;
    lune_icmp_hdr_t *icmph;
    lune_icmpv6_opt_slla_t *opt;
    lune_ipv6_addr_t dst_sn_mc_addr;

    pbuf_init_send_pbuf(&pbuf, lbuf, 0, PBUF_MAX_RSVD_HDR_LEN, IP_IS_DPDK(ipv6p));

    buf = pbuf_move_down(&pbuf, LUNE_IPV6_ADDR_LEN + LUNE_ICMPV6_OPT_SLLA_LEN);
    LUNE_IPV6_CPY(buf, dst_addr);
    opt = (lune_icmpv6_opt_slla_t *)(buf + LUNE_IPV6_ADDR_LEN);
    opt->type = LUNE_ICMPV6_NB_SOLICIT_OPT_SLLA;
    opt->len = 1;
    lune_assert(!ip_get_mac(ipv6p, opt->src_mac));

    IPV6_CONV_UC_TO_SN_MC(dst_addr, &dst_sn_mc_addr);

    icmph = (lune_icmp_hdr_t *)pbuf_move_down(&pbuf, LUNE_ICMP_HDR_LEN);
    icmpv6_build_hdr(icmph,
        LUNE_ICMPV6_NB_SOLICIT,
        0,
        0,
        LUNE_IPV6_ADDR_LEN + LUNE_ICMPV6_OPT_SLLA_LEN,
        ipv6p,
        &dst_sn_mc_addr);

    return ipv6_output(ipv6p, &dst_sn_mc_addr, LUNE_IP_PROTO_ICMPV6, &pbuf);
}

static inline int icmpv6_process_echo_request(ip_t *ipv6p,
    const lune_ipv6_hdr_t *ipv6h, const lune_icmp_hdr_t *icmph, pbuf_t *rx_pbuf)
{
    unsigned char lbuf[PBUF_MAX_RSVD_HDR_LEN + IP_MAX_PAYLOAD_BUF_SIZE];
    pbuf_t tx_pbuf;
    char ipv6_str[LUNE_IPV6_MAX_ADDR_STR_LEN];
    lune_ip_addr_t dst_ip;
    int err;

    dst_ip.is_ipv6 = 1;
    LUNE_IPV6_CPY(&dst_ip.ipv6, &((const lune_ipv6_hdr_t *)ipv6h)->src_addr);

    pbuf_init_send_pbuf(&tx_pbuf, lbuf, PBUF_GET_PAYLOAD_LEN(rx_pbuf), PBUF_MAX_RSVD_HDR_LEN, 0);
    memcpy(PBUF_GET_PAYLOAD(&tx_pbuf),
        PBUF_GET_PAYLOAD(rx_pbuf), PBUF_GET_PAYLOAD_LEN(rx_pbuf));

    if (0 != (err = icmp_output(ipv6p,
        &dst_ip, LUNE_ICMPV6_ECHO_REPLY, 0, icmph->data, &tx_pbuf))) {
        lune_log(LUNE_INFO, "failed to reply to ping %s request",
            lune_ipv6_to_str(&ipv6p->ipv6.ip, ipv6_str, LUNE_IPV6_MAX_ADDR_STR_LEN));
    }

    return err;
}

static inline int icmpv6_process_nb_solicit(ip_t *ipv6p,
    const lune_ipv6_hdr_t *ipv6h, const lune_icmp_hdr_t *icmph)
{
    int err;
    lune_ip_addr_t dst_ip;
    const lune_icmpv6_opt_hdr_t *rx_icmpv6oh;
    lune_icmpv6_opt_tlla_t *tx_opt;
    unsigned char lbuf[PBUF_MAX_RSVD_HDR_LEN], *buf;
    pbuf_t pbuf;
    char ipv6_str[LUNE_IPV6_MAX_ADDR_STR_LEN];

    rx_icmpv6oh = (const lune_icmpv6_opt_hdr_t *)((const unsigned char *)icmph
        + LUNE_ICMP_HDR_LEN + LUNE_IPV6_ADDR_LEN);
    if (unlikely(icmph->code != 0
        || rx_icmpv6oh->type != LUNE_ICMPV6_NB_SOLICIT_OPT_SLLA)
        || rx_icmpv6oh->len != 1) {
        /* source link-layer address option is expected */
        return 0;
    }

#ifdef LUNE_DEBUG
    lune_assert(!LUNE_IPV6_CMP(&ipv6p->ipv6.ip, icmph + 1));
#endif

    dst_ip.is_ipv6 = 1;
    LUNE_IPV6_CPY(&dst_ip.ipv6, &ipv6h->src_addr);
    if (0 != (err = nb_upsert(rx_icmpv6oh->val, &dst_ip, NET_IF_GET_CURR_NET_IF()))) {
        nb_log_error("failed to upsert neighbor", &dst_ip, err);
        return err;
    }

    pbuf_init_send_pbuf(&pbuf, lbuf, 0, PBUF_MAX_RSVD_HDR_LEN, IP_IS_DPDK(ipv6p));
    buf = pbuf_move_down(&pbuf, LUNE_IPV6_ADDR_LEN + LUNE_ICMPV6_OPT_TLLA_LEN);
    LUNE_IPV6_CPY(buf, &ipv6p->ipv6.ip);
    tx_opt = (lune_icmpv6_opt_tlla_t *)(buf + LUNE_IPV6_ADDR_LEN);
    tx_opt->type = LUNE_ICMPV6_NB_SOLICIT_OPT_TLLA;
    tx_opt->len = 1;
    lune_assert(!ip_get_mac(ipv6p, tx_opt->tgt_mac));

    if (0 != (err = icmp_output(ipv6p, &dst_ip, LUNE_ICMPV6_NB_ADVERT, 0, 0, &pbuf))) {
        lune_log(LUNE_WARN, "failed to reply to nd request for %s",
            lune_ipv6_to_str(&ipv6h->dst_addr, ipv6_str, LUNE_IPV6_MAX_ADDR_STR_LEN));
    }

    return err;
}

static inline int icmpv6_process_nb_advert(ip_t *ipv6p __attribute__((unused)),
    const lune_ipv6_hdr_t *ipv6h __attribute__((unused)), const lune_icmp_hdr_t *icmph)
{
    const lune_icmpv6_opt_hdr_t *icmpv6oh;

    icmpv6oh = (const lune_icmpv6_opt_hdr_t *)((const unsigned char *)icmph
        + LUNE_ICMP_HDR_LEN + LUNE_IPV6_ADDR_LEN);
    if (unlikely(icmph->code != 0
        || icmpv6oh->type != LUNE_ICMPV6_NB_SOLICIT_OPT_TLLA)
        || icmpv6oh->len != 1) {
        /* target link-layer address option is expected */
        return 0;
    }

#ifdef LUNE_DEBUG
    lune_assert(!LUNE_IPV6_CMP(&ipv6h->src_addr, icmph + 1));
#endif

    /* nb_upsert has been done at ipv6 layer */
    return 0;
}

int icmpv4_input(ip_t *ipv4p, const void *ipv4h, pbuf_t *rx_pbuf)
{
    socket_t *sk, psd_sk;
    icmp_pcb_t *pcb;
    lune_icmp_hdr_t *icmph;
    char ipv4_str[LUNE_IPV4_MAX_ADDR_STR_LEN];
    lune_ip_addr_t dst_ip;
    int err;

#ifdef LUNE_DEBUG
    lune_assert(NULL != ipv4p);
#endif

    icmph = (lune_icmp_hdr_t *)pbuf_move_up(rx_pbuf, LUNE_ICMP_HDR_LEN);

    psd_sk.type = LUNE_SOCKET_ICMP;
    psd_sk.ops = &g_socket_ops_icmp;
    psd_sk.pcb.icmp.ipp = ipv4p;
    if (NULL != (sk = socket_find(&psd_sk))) {
        /* hold it till icmpv4_input() returns */
        socket_hold(sk);

        pcb = &sk->pcb.icmp;
        if (likely(NULL != pcb->cb.recvfrom)) {
            dst_ip.is_ipv6 = 0;
            dst_ip.ipv4 = ((const lune_ipv4_hdr_t *)ipv4h)->src_addr;

            SOCKET_PUSH_CB_SK(sk);
            pcb->cb.recvfrom(pcb->cb.data, (const lune_ip_addr_t *)&dst_ip,
                (const unsigned char *)icmph, LUNE_ICMP_HDR_LEN + PBUF_GET_PAYLOAD_LEN(rx_pbuf));
            SOCKET_POP_CB_SK();
        }

        socket_put(sk);
        return 0;
    }

    if (LUNE_ICMPV4_ECHO_REQUEST == icmph->type) {
        unsigned char lbuf[PBUF_MAX_RSVD_HDR_LEN + IP_MAX_PAYLOAD_BUF_SIZE];
        pbuf_t tx_pbuf;
        dst_ip.is_ipv6 = 0;
        dst_ip.ipv4 = ((const lune_ipv4_hdr_t *)ipv4h)->src_addr;

        pbuf_init_send_pbuf(&tx_pbuf, lbuf, PBUF_GET_PAYLOAD_LEN(rx_pbuf), PBUF_MAX_RSVD_HDR_LEN, 0);
        memcpy(PBUF_GET_PAYLOAD(&tx_pbuf),
            PBUF_GET_PAYLOAD(rx_pbuf), PBUF_GET_PAYLOAD_LEN(rx_pbuf));

        if (0 != (err = icmp_output(ipv4p,
            &dst_ip, LUNE_ICMPV4_ECHO_REPLY, 0, icmph->data, &tx_pbuf))) {
            lune_log(LUNE_INFO, "failed to reply to ping %s request",
                lune_ipv4_to_str(ipv4p->ipv4.ip, ipv4_str, LUNE_IPV4_MAX_ADDR_STR_LEN));
        }

        return err;
    }

    return 0;
}

int icmpv6_input(ip_t *ipv6p, const void *ipv6h, pbuf_t *pbuf)
{
    socket_t *sk, psd_sk;
    icmp_pcb_t *pcb;
    lune_icmp_hdr_t *icmph;
    lune_ip_addr_t dst_ip;

    icmph = (lune_icmp_hdr_t *)pbuf_move_up(pbuf, LUNE_ICMP_HDR_LEN);

    if (ICMPV6_IS_NB_MSG(icmph)) {
        goto SKIP_SOCKET;
    }

#ifdef LUNE_DEBUG
    lune_assert(NULL != ipv6p);
#endif

    psd_sk.type = LUNE_SOCKET_ICMP;
    psd_sk.ops = &g_socket_ops_icmp;
    psd_sk.pcb.icmp.ipp = ipv6p;
    if (NULL != (sk = socket_find(&psd_sk))) {
        /* hold it till icmpv6_input() returns */
        socket_hold(sk);

        pcb = &sk->pcb.icmp;
        if (likely(NULL != pcb->cb.recvfrom)) {
            dst_ip.is_ipv6 = 1;
            LUNE_IPV6_CPY(&dst_ip.ipv6, &((const lune_ipv6_hdr_t *)ipv6h)->src_addr);

            SOCKET_PUSH_CB_SK(sk);
            pcb->cb.recvfrom(pcb->cb.data, (const lune_ip_addr_t *)&dst_ip,
                (const unsigned char *)icmph, LUNE_ICMP_HDR_LEN + PBUF_GET_PAYLOAD_LEN(pbuf));
            SOCKET_POP_CB_SK();
        }

        socket_put(sk);
        return 0;
    }

SKIP_SOCKET:
    switch (icmph->type) {
    case LUNE_ICMPV6_ECHO_REQUEST:
        return icmpv6_process_echo_request(ipv6p, (const lune_ipv6_hdr_t *)ipv6h, icmph, pbuf);
    case LUNE_ICMPV6_NB_SOLICIT:
        return icmpv6_process_nb_solicit(ipv6p, (const lune_ipv6_hdr_t *)ipv6h, icmph);
    case LUNE_ICMPV6_NB_ADVERT:
        return icmpv6_process_nb_advert(ipv6p, (const lune_ipv6_hdr_t *)ipv6h, icmph);
    default:
        break;
    }

    return 0;
}

static unsigned short icmp_socket_get_max_hdr_len(socket_t *sk)
{
    icmp_pcb_t *pcb = &sk->pcb.icmp;
    unsigned short sub_entry_hdr_len;

    lune_assert(NULL != pcb->ipp);

    sub_entry_hdr_len = pbuf_get_max_hdr_len(
        IP_IS_IPV6(pcb->ipp) ? LUNE_ID_IPV6 : LUNE_ID_IPV4, pcb->ipp);
    return LUNE_ICMP_HDR_LEN + sub_entry_hdr_len;
}

static int icmp_socket_create(socket_t *sk)
{
    icmp_pcb_t *pcb = &sk->pcb.icmp;

    pcb->cb.recvfrom = NULL;
    pcb->cb.data = NULL;
    pcb->ipp = NULL;

    return 0;
}

static int icmp_socket_bind(socket_t *sk, const void *arg, unsigned int arg_len)
{
    ip_t *ipp;
    icmp_pcb_t *pcb;
    int err;

    if (unlikely(arg_len != sizeof(unsigned int))) {
        return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
    }

    pcb = &sk->pcb.icmp;
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
    if (unlikely(0 != (err = socket_insert(sk)))) {
        pcb->ipp = NULL;
        return err;
    }

    ip_hold(ipp);
    IP_SET_L4_SOCKET(ipp);

    sk->rsvd_hdr_len = icmp_socket_get_max_hdr_len(sk);

    return 0;
}

static int icmp_socket_sendto(socket_t *sk, const unsigned char *buf, unsigned int len,
    const void *dst_addr, unsigned int dst_addr_len, const lune_icmp_sendto_arg_t *arg, unsigned int arg_len)
{
    icmp_pcb_t *pcb;
    unsigned char lbuf[PBUF_MAX_RSVD_HDR_LEN + IP_MAX_PAYLOAD_BUF_SIZE];
    pbuf_t pbuf;

    if (unlikely(dst_addr_len != sizeof(lune_ip_addr_t)
        || NULL == arg || arg_len != sizeof(lune_icmp_sendto_arg_t))) {
        return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
    }

    pcb = &sk->pcb.icmp;

    if (unlikely(NULL == pcb->ipp)) {
        return ERR_SET_ERR(LUNE_ERR_NOT_BOUND);
    }

    if (unlikely(IP_IS_DELETED(pcb->ipp))) {
        return ERR_SET_ERR(LUNE_ERR_ALREADY_DELETED);
    }

    if (unlikely(!IP_IS_PAYLOAD_LEN_VALID(pcb->ipp, len + LUNE_ICMP_HDR_LEN))) {
        return ERR_SET_ERR(LUNE_ERR_OVERSIZED_PKT);
    }

    pbuf_init_send_pbuf(&pbuf, lbuf, len, PBUF_MAX_RSVD_HDR_LEN, IP_IS_DPDK(pcb->ipp));
    if (likely(len > 0)) {
        memcpy(PBUF_GET_HDR(&pbuf), buf, len);
    }

    return icmp_output(pcb->ipp, (const lune_ip_addr_t *)dst_addr,
        arg->type, arg->code, arg->data, &pbuf);
}

static int icmp_socket_get_opt(socket_t *sk, lune_socket_opt_en opt, unsigned char *opt_val, unsigned int opt_len)
{
    icmp_pcb_t *pcb = &sk->pcb.icmp;

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

static int icmp_socket_set_opt(socket_t *sk,
    lune_socket_opt_en opt, const unsigned char *opt_val, unsigned int opt_len)
{
    icmp_pcb_t *pcb = &sk->pcb.icmp;

    switch (opt) {
    case LUNE_SOCKET_OPT_SET_CALLBACK:
        if (NULL == opt_val
            || opt_len != sizeof(lune_icmp_socket_callback_t)) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        pcb->cb.recvfrom = ((const lune_icmp_socket_callback_t *)opt_val)->recvfrom;
        pcb->cb.data = ((const lune_icmp_socket_callback_t *)opt_val)->data;
        break;
    default:
        return ERR_SET_ERR(LUNE_ERR_OPT_NOT_FOUND);
    }

    return 0;
}

static int icmp_socket_close(socket_t *sk)
{
    icmp_pcb_t *pcb = &sk->pcb.icmp;

    pcb->cb.recvfrom = NULL;

    if (NULL != pcb->ipp) {
        lune_assert(!socket_remove(sk));
        ip_put(pcb->ipp);
        pcb->ipp = NULL;
    } else {
        lune_assert(!socket_is_added(sk));
    }

    return 0;
}

static unsigned int icmp_socket_hash(socket_pcb_un *pcb)
{
    return IP_IS_IPV6(pcb->icmp.ipp)
        ? ((lune_ntohl(pcb->icmp.ipp->ipv6.ip.addr[3]) << 16) & SOCKET_HTABLE_MASK)
        : ((pcb->icmp.ipp->ipv4.ip << 16) & SOCKET_HTABLE_MASK);
}

static int icmp_socket_compare(socket_pcb_un *pcb1, socket_pcb_un *pcb2)
{
    return pcb1->icmp.ipp == pcb2->icmp.ipp ? 0 : 1;
}

socket_ops_t g_socket_ops_icmp = {
    .create = (socket_create_func_t)icmp_socket_create,
    .bind = (socket_bind_func_t)icmp_socket_bind,
    .connect = NULL,
    .listen = NULL,
    .send = NULL,
    .send_pkts = NULL,
    .sendto = (socket_sendto_func_t)icmp_socket_sendto,
    .get_opt = (socket_get_opt_func_t)icmp_socket_get_opt,
    .set_opt = (socket_set_opt_func_t)icmp_socket_set_opt,
    .close = (socket_close_func_t)icmp_socket_close,
    .hash = (socket_hash_func_t)icmp_socket_hash,
    .compare = (socket_compare_func_t)icmp_socket_compare,
    .get_max_hdr_len = (socket_get_max_hdr_len_func_t)icmp_socket_get_max_hdr_len,
};

int icmp_local_init(void)
{
    return 0;
}

void icmp_local_fini(void)
{
}
