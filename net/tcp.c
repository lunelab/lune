/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2024 Lune Reseau, Inc.
 */

#include "lune/ip.h"
#include "lune/list.h"
#include "lune/log.h"
#include "lune/net.h"
#include "lune/os/linux.h"
#include "lune/time.h"

#include "kernel/timer.h"
#include "lib/common.h"
#include "lib/csum.h"
#include "net/ip.h"
#include "net/tcp.h"

#define TCP_IS_SOCKET_CLOSED(sk)    (TCP_CLOSED == ((socket_x_t *)(sk))->pcb.tcp.state)

#define TCP_PRINT_4TUPLE_STR_LEN    (256)
static __thread char s_4tuple_str[TCP_PRINT_4TUPLE_STR_LEN];

#define TCP_MAX_HDR_LEN             (60)

#define TCP_MIN_SS_THRESH_SEG_NUM   (2)
#define TCP_DEFAULT_WND_SIZE        (65535)
#define TCP_MAX_CWND_SIZE           (65535)

#define TCP_FLAG_FIN                0x01
#define TCP_FLAG_SYN                0x02
#define TCP_FLAG_RST                0x04
#define TCP_FLAG_PSH                0x08
#define TCP_FLAG_ACK                0x10
#define TCP_FLAG_URG                0x20
/* flag for internal use */
#define TCP_FLAG_DATA               0x40

#define TCP_FLAG_FIN_ACK            (TCP_FLAG_FIN | TCP_FLAG_ACK)
#define TCP_FLAG_SYN_ACK            (TCP_FLAG_SYN | TCP_FLAG_ACK)
#define TCP_FLAG_PSH_ACK            (TCP_FLAG_PSH | TCP_FLAG_ACK)
#define TCP_FLAG_RST_ACK            (TCP_FLAG_RST | TCP_FLAG_ACK)
#define TCP_FLAG_DATA_ACK           (TCP_FLAG_DATA | TCP_FLAG_ACK)
#define TCP_FLAG_DATA_FIN_ACK       (TCP_FLAG_DATA | TCP_FLAG_FIN | TCP_FLAG_ACK)
#define TCP_FLAG_DATA_PSH_ACK       (TCP_FLAG_DATA | TCP_FLAG_PSH | TCP_FLAG_ACK)
#define TCP_FLAG_DATA_FIN_PSH_ACK   (TCP_FLAG_DATA | TCP_FLAG_FIN | TCP_FLAG_PSH | TCP_FLAG_ACK)

#define TCP_OPT_EOL                 (0)
#define TCP_OPT_NOP                 (1)
#define TCP_OPT_MSS                 (2)
#define TCP_OPT_WS                  (3)
#define TCP_OPT_SACK_PERM           (4)

#define TCP_OPT_MSS_LEN             (4)
#define TCP_OPT_WS_LEN              (3)
#define TCP_OPT_SACK_PERM_LEN       (2)

#define TCP_DEFAULT_DELACK_INTVL                (250 * LUNE_TIME_MILLISECOND)
#define TCP_DEFAULT_TWAIT_INTVL                 (2 * LUNE_TIME_SECOND)
#define TCP_DEFAULT_DELAY_RST_INTVL             (100 * LUNE_TIME_MILLISECOND)

#define TCP_LISTEN_IS_BACKLOG_UNLIMITED(pcb)    \
    (LUNE_TCP_LISTEN_BACKLOG_UNLIMITED == (pcb)->backlog)

#define TCP_GET_RETRANS_INTVL(t)    (s_tcp_retrans_intvl[t])
#define TCP_RETRANS_TIMES           (4)
static __thread unsigned int s_tcp_retrans_intvl[TCP_RETRANS_TIMES + 1] = {0};

#define TCP_INIT_SEQ_STEP           (64000)
#define TCP_GET_NEW_SEQ_NO()        (s_tcp_init_seq_no += TCP_INIT_SEQ_STEP)
static __thread unsigned int s_tcp_init_seq_no;

#define tcp_process_rst(sk)         tcp_close_socket(sk, LUNE_TCP_SOCKET_CLOSE_RST)
#define tcp_process_keep_alive_timeout(pcb, sk) \
    do {                                        \
        lune_assert(TCP_KEEP_ALIVE_ON(pcb));    \
        TCP_KEEP_ALIVE_TURN_OFF(pcb);           \
        tcp_close_socket(sk, LUNE_TCP_SOCKET_CLOSE_KEEP_ALIVE_TIMEOUT); \
    } while (0)

static __thread unsigned int s_tcp_listen_socket_cnt;
static __thread unsigned int s_tcp_batch_listen_socket_cnt;
static __thread unsigned int s_tcp_peer_listen_socket_cnt;

#define TCP_GET_HDR_LEN(tcph)       ((0x0f & (((lune_tcp_hdr_t *)tcph)->hdr_len >> 4)) << 2)
#define TCP_GET_OPT_HDR_LEN(tcph)   (TCP_GET_HDR_LEN(tcph) - LUNE_TCP_HDR_LEN)

#pragma pack(1)
/* option header for EOL, NOP */
typedef struct _tcp_opt_min_hdr {
    unsigned char type;
} tcp_opt_min_hdr_t;

/* option header for others */
typedef struct _tcp_opt_hdr {
    unsigned char type;
    unsigned char len;
} tcp_opt_hdr_t;
#pragma pack()

#define TCP_OPT_MIN_HDR_LEN         (sizeof(tcp_opt_min_hdr_t))
#define TCP_OPT_HDR_LEN             (sizeof(tcp_opt_hdr_t))

/* MUST BE THE SAME ORDER AS tcp_state_en */
const char *g_tcp_state_str[] =
{
    "TCP_SYNR",
    "TCP_SYNS",
    "TCP_EST",
    "TCP_FINWT1",
    "TCP_FINWT2",
    "TCP_CLOSING",
    "TCP_TWAIT",
    "TCP_CLWAIT",
    "TCP_LASTACK",
    "TCP_LISTEN",
    "TCP_CLOSED",
};

char *tcp_print_pcb_4tuple(tcp_pcb_t *pcb)
{
    char src_ip_str[LUNE_IPV6_MAX_ADDR_STR_LEN], dst_ip_str[LUNE_IPV6_MAX_ADDR_STR_LEN];

    lune_assert(NULL != pcb);
    lune_assert(NULL != pcb->ipp);

    if (IP_IS_IPV6(pcb->ipp)) {
        sprintf(s_4tuple_str, "<%s:%d, %s:%d>",
            lune_ipv6_to_str(&pcb->ipp->ipv6.ip, src_ip_str, LUNE_IPV6_MAX_ADDR_STR_LEN),
            pcb->src_port,
            lune_ipv6_to_str(&pcb->dst_ip.ipv6, dst_ip_str, LUNE_IPV6_MAX_ADDR_STR_LEN),
            pcb->dst_port);
    } else {
        sprintf(s_4tuple_str, "<%s:%d, %s:%d>",
            lune_ipv4_to_str(pcb->ipp->ipv4.ip, src_ip_str, LUNE_IPV6_MAX_ADDR_STR_LEN),
            pcb->src_port,
            lune_ipv4_to_str(pcb->dst_ip.ipv4, dst_ip_str, LUNE_IPV6_MAX_ADDR_STR_LEN),
            pcb->dst_port);
    }

    return s_4tuple_str;
}

static inline char *tcp_print_4tuple(ip_t *ipp, lune_ip_addr_t *dst_addr,
    unsigned short src_port, unsigned short dst_port)
{
    char src_ip_str[LUNE_IPV6_MAX_ADDR_STR_LEN], dst_ip_str[LUNE_IPV6_MAX_ADDR_STR_LEN];

    lune_assert(NULL != ipp);

    if (IP_IS_IPV6(ipp)) {
        sprintf(s_4tuple_str, "<%s:%d, %s:%d>",
            lune_ipv6_to_str(&ipp->ipv6.ip, src_ip_str, LUNE_IPV6_MAX_ADDR_STR_LEN),
            src_port,
            lune_ipv6_to_str(&dst_addr->ipv6, dst_ip_str, LUNE_IPV6_MAX_ADDR_STR_LEN),
            dst_port);
    } else {
        sprintf(s_4tuple_str, "<%s:%d, %s:%d>",
            lune_ipv4_to_str(ipp->ipv4.ip, src_ip_str, LUNE_IPV6_MAX_ADDR_STR_LEN),
            src_port,
            lune_ipv4_to_str(dst_addr->ipv4, dst_ip_str, LUNE_IPV6_MAX_ADDR_STR_LEN),
            dst_port);
    }

    return s_4tuple_str;
}

static inline unsigned short tcp_calc_csum(lune_tcp_hdr_t *tcph,
    ip_t *ipp,
    lune_ip_addr_t *dst_ip,
    unsigned short tcp_len)
{
    unsigned int sum;

    sum = csum_partial((unsigned char *)tcph, tcp_len, 0);

    if (IP_IS_IPV6(ipp)) {
        lune_ipv6_psd_hdr_t ipv6h;
        LUNE_IPV6_CPY(ipv6h.src_addr.addr, ipp->ipv6.ip.addr);
        LUNE_IPV6_CPY(ipv6h.dst_addr.addr, dst_ip->ipv6.addr);
        ipv6h.len = lune_htons(tcp_len);
        *(unsigned int *)ipv6h.zeros = 0;
        ipv6h.proto = LUNE_IP_PROTO_TCP;
        sum = csum_partial((unsigned char *)&ipv6h, sizeof(lune_ipv6_psd_hdr_t), sum);
    } else {
        lune_ipv4_psd_hdr_t ipv4h;
        ipv4h.src_addr = lune_htonl(ipp->ipv4.ip);
        ipv4h.dst_addr = lune_htonl(dst_ip->ipv4);
        ipv4h.z = 0;
        ipv4h.proto = LUNE_IP_PROTO_TCP;
        ipv4h.len = lune_htons(tcp_len);
        sum = csum_partial((unsigned char *)&ipv4h, sizeof(lune_ipv4_psd_hdr_t), sum);
    }

    return csum_fold(sum);
}

int lune_tcp_calc_csum(lune_tcp_hdr_t *tcph,
    lune_ip_addr_t *src_ip,
    lune_ip_addr_t *dst_ip,
    unsigned short tcp_len,
    unsigned short *pcsum)
{
    unsigned int sum;

    if (unlikely(src_ip->is_ipv6 != dst_ip->is_ipv6)) {
        return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
    }

    sum = csum_partial((unsigned char *)tcph, tcp_len, 0);

    if (src_ip->is_ipv6) {
        lune_ipv6_psd_hdr_t ipv6h;
        LUNE_IPV6_CPY(ipv6h.src_addr.addr, src_ip->ipv6.addr);
        LUNE_IPV6_CPY(ipv6h.dst_addr.addr, dst_ip->ipv6.addr);
        ipv6h.len = lune_htons(tcp_len);
        *(unsigned int *)ipv6h.zeros = 0;
        ipv6h.proto = LUNE_IP_PROTO_TCP;
        sum = csum_partial((unsigned char *)&ipv6h, sizeof(lune_ipv6_psd_hdr_t), sum);
    } else {
        lune_ipv4_psd_hdr_t ipv4h;
        ipv4h.src_addr = lune_htonl(src_ip->ipv4);
        ipv4h.dst_addr = lune_htonl(dst_ip->ipv4);
        ipv4h.z = 0;
        ipv4h.proto = LUNE_IP_PROTO_TCP;
        ipv4h.len = lune_htons(tcp_len);
        sum = csum_partial((unsigned char *)&ipv4h, sizeof(lune_ipv4_psd_hdr_t), sum);
    }

    *pcsum = csum_fold(sum);
    return 0;
}

static inline void tcp_build_hdr(lune_tcp_hdr_t *tcph,
    ip_t *ipp,
    lune_ip_addr_t *dst_ip,
    unsigned short src_port,
    unsigned short dst_port,
    unsigned int seq_no,
    unsigned int ack_no,
    unsigned char flags,
    unsigned char opt_len,
    unsigned short win_size,
    unsigned int data_len,
    unsigned int hw_csum_flag)
{
    tcph->src_port = lune_htons(src_port);
    tcph->dst_port =  lune_htons(dst_port);
    tcph->seq_no = lune_htonl(seq_no);
    tcph->ack_no = lune_htonl(ack_no);
    tcph->hdr_len = (LUNE_TCP_HDR_LEN + opt_len) << 2;
    tcph->flags = flags;
    tcph->win_size = lune_htons(win_size);
    tcph->urg_ptr = 0;
    tcph->csum = 0;
    if (!hw_csum_flag) {
        tcph->csum = tcp_calc_csum(tcph, ipp, dst_ip, LUNE_TCP_HDR_LEN + data_len + opt_len);
    }
}

static inline int tcp_send_ctrl_pkt(ip_t *ipp,
    lune_ip_addr_t *dst_ip,
    unsigned short src_port,
    unsigned short dst_port,
    unsigned int seq_no,
    unsigned int ack_no,
    unsigned char flags,
    unsigned short win_size)
{
    unsigned char lbuf[PBUF_MAX_RSVD_HDR_LEN + LUNE_TCP_HDR_LEN];
    pbuf_t pbuf;
    lune_tcp_hdr_t *tcph;

    pbuf_init_send_pbuf(&pbuf, lbuf, LUNE_TCP_HDR_LEN, PBUF_MAX_RSVD_HDR_LEN, IP_IS_DPDK(ipp));

    tcph = (lune_tcp_hdr_t *)PBUF_GET_HDR(&pbuf);
    tcp_build_hdr(tcph, ipp, dst_ip, src_port, dst_port, seq_no, ack_no,
        flags, 0, win_size, 0, IP_IS_HW_TX_TCP_CSUM(ipp));

    pbuf.l4_len = LUNE_TCP_HDR_LEN;
    PBUF_SET_L4_TYPE_TCP(&pbuf);
    pbuf.tcp.data_len = 0;

    return ip_output_nofrag(ipp, dst_ip, LUNE_IP_PROTO_TCP, &pbuf);
}

static inline void tcp_free_send_pbuf(tcp_pcb_t *pcb)
{
    pbuf_t *p, *p2;

    dlist_for_each_node_safe(p, p2, &pcb->send_buf_list, node) {
        dlist_del(&p->node);
        pbuf_put_last(p);
    }
}

static inline void tcp_free_all_pbuf(tcp_pcb_t *pcb)
{
    pbuf_t *p, *p2;

    dlist_for_each_node_safe(p, p2, &pcb->send_buf_list, node) {
        dlist_del(&p->node);
        pbuf_put_last(p);
    }

    dlist_for_each_node_safe(p, p2, &pcb->unack_buf_list, node) {
        dlist_del(&p->node);
        pbuf_put(p);
    }

    dlist_for_each_node_safe(p, p2, &pcb->unordered_buf_list, node) {
        dlist_del(&p->node);
        pbuf_free_pbuf(p);
    }
}

static inline int tcp_enqueue_ctrl(socket_x_t *sk, unsigned char flags)
{
    tcp_pcb_t *pcb = &sk->pcb.tcp;
    pbuf_t *pbuf;
    lune_tcp_hdr_t *tcph;
    unsigned short win_size, opt_len;

    if (unlikely(NULL == (pbuf = pbuf_alloc_send_pbuf(0, sk->rsvd_hdr_len)))) {
        return ERR_GET_LAST_ERR();
    }

    if (flags & TCP_FLAG_SYN) {
        tcp_opt_hdr_t *tcpoh;
        /* add mss option */
        opt_len = TCP_OPT_MSS_LEN;
        tcph = (lune_tcp_hdr_t *)pbuf_move_down(pbuf, LUNE_TCP_HDR_LEN + TCP_OPT_MSS_LEN);
        tcpoh = (tcp_opt_hdr_t *)(tcph + 1);
        tcpoh->type = TCP_OPT_MSS;
        tcpoh->len = TCP_OPT_MSS_LEN;
        *(unsigned short  *)((unsigned char *)tcpoh + TCP_OPT_HDR_LEN) = lune_htons(pcb->mss);
    } else {
        opt_len = 0;
        tcph = (lune_tcp_hdr_t *)pbuf_move_down(pbuf, LUNE_TCP_HDR_LEN);
    }

    /* silly window avoidance */
    if (unlikely(pcb->recv_wnd < pcb->mss)) {
        win_size = 0;
    } else {
        win_size = pcb->recv_wnd;
    }

    pbuf->l4_len = LUNE_TCP_HDR_LEN + opt_len;
    PBUF_SET_L4_TYPE_TCP(pbuf);
    pbuf->tcp.hdr = tcph;
    pbuf->tcp.retrans_times = 0;
    pbuf->tcp.data_len = 0;

    tcp_build_hdr(tcph, pcb->ipp, &pcb->dst_ip, pcb->src_port, pcb->dst_port,
        pcb->send_lbb, pcb->recv_nxt, flags, opt_len, win_size, 0, IP_IS_HW_TX_TCP_CSUM(pcb->ipp));

    pcb->send_lbb += 1;

    dlist_add_tail(&pbuf->node, &pcb->send_buf_list);
    pbuf_hold(pbuf);

    return 0;
}

/*
    caller MUST guarantee data to be sent within congestion window
*/
static inline int tcp_enqueue_data(socket_x_t *sk,
    const unsigned char *data, unsigned int len, unsigned char flags)
{
    tcp_pcb_t *pcb = &sk->pcb.tcp;
    pbuf_t *pbuf;
    lune_tcp_hdr_t *tcph;

    if (unlikely(NULL == (pbuf = pbuf_alloc_send_pbuf(len, sk->rsvd_hdr_len)))) {
        goto ERR_1;
    }

    memcpy(PBUF_GET_HDR(pbuf), data, len);
    tcph = (lune_tcp_hdr_t *)pbuf_move_down(pbuf, LUNE_TCP_HDR_LEN);
    pbuf->l4_len = LUNE_TCP_HDR_LEN + len;
    PBUF_SET_L4_TYPE_TCP(pbuf);
    pbuf->tcp.hdr = tcph;
    pbuf->tcp.retrans_times = 0;
    pbuf->tcp.data_len = len;

    if (unlikely(pcb->recv_wnd < TCP_DEFAULT_WND_SIZE
        && !TCP_ZERO_WIN_ON(pcb))) {
        /*
            keep an eye on silly window syndrome though it should
            NEVER happen since received data is passed to application
            right away instead of being cached in tcp stack, except
            for the case that zero windows is applied on purpose
        */
        lune_log(LUNE_WARN, "unexpected receiving window size %d on tcp connection %s",
            pcb->recv_wnd, tcp_print_pcb_4tuple(pcb));
        ERR_SET_ERR(LUNE_ERR_TCP_INTERNAL);
        goto ERR_2;
    }

    tcp_build_hdr(tcph, pcb->ipp, &pcb->dst_ip, pcb->src_port, pcb->dst_port,
        pcb->send_lbb, pcb->recv_nxt, flags, 0, pcb->recv_wnd, len, IP_IS_HW_TX_TCP_CSUM(pcb->ipp));

    pcb->send_lbb += len;

    dlist_add_tail(&pbuf->node, &pcb->send_buf_list);
    pbuf_hold(pbuf);

    return len;

ERR_2:
    pbuf_free_pbuf(pbuf);

ERR_1:
    return ERR_GET_LAST_ERR();
}

/*
    caller MUST guarantee data to be sent within congestion window
*/
static inline int tcp_enqueue_data_x(socket_x_t *sk,
    lune_socket_send_pkt_t *pkts, unsigned int offset, unsigned int len, unsigned char flags)
{
    tcp_pcb_t *pcb = &sk->pcb.tcp;
    pbuf_t *pbuf;
    lune_tcp_hdr_t *tcph;

    if (unlikely(NULL == (pbuf = pbuf_alloc_send_pbuf(len, sk->rsvd_hdr_len)))) {
        goto ERR_1;
    }

    tcph = (lune_tcp_hdr_t *)pbuf_move_down(pbuf, LUNE_TCP_HDR_LEN);
    pbuf->l4_len = LUNE_TCP_HDR_LEN + len;
    PBUF_SET_L4_TYPE_TCP(pbuf);
    pbuf->tcp.hdr = tcph;
    pbuf->tcp.retrans_times = 0;
    pbuf->tcp.data_len = len;

    if ((pkts->len - offset) >= len) {
        memcpy(PBUF_GET_PAYLOAD(pbuf), pkts->buf + offset, len);
    } else {
        memcpy(PBUF_GET_PAYLOAD(pbuf), pkts->buf + offset, pkts->len - offset);
        offset = pkts->len - offset;    /* reuse offset for different purpose */
        pkts++;
        while ((offset + pkts->len) < len) {
            memcpy(PBUF_GET_PAYLOAD(pbuf) + offset, pkts->buf, pkts->len);
            offset += pkts->len;
            pkts++;
        }
        memcpy(PBUF_GET_PAYLOAD(pbuf) + offset, pkts->buf, len - offset);
    }

    if (unlikely(pcb->recv_wnd < TCP_DEFAULT_WND_SIZE)) {
        /*
            keep an eye on silly window syndrome though it should
            NEVER happen since received data is passed to application
            right away instead of being buffered in tcp stack
        */
        lune_log(LUNE_WARN, "unexpected receiving window size %d on tcp connection %s",
            pcb->recv_wnd, tcp_print_pcb_4tuple(pcb));
        ERR_SET_ERR(LUNE_ERR_TCP_INTERNAL);
        goto ERR_2;
    }

    tcp_build_hdr(tcph, pcb->ipp, &pcb->dst_ip, pcb->src_port, pcb->dst_port,
        pcb->send_lbb, pcb->recv_nxt, flags, 0, pcb->recv_wnd, len, IP_IS_HW_TX_TCP_CSUM(pcb->ipp));

    pcb->send_lbb += len;

    dlist_add_tail(&pbuf->node, &pcb->send_buf_list);
    pbuf_hold(pbuf);

    return len;

ERR_2:
    pbuf_free_pbuf(pbuf);

ERR_1:
    return ERR_GET_LAST_ERR();
}

/*
    caller MUST ensure send_buf_list is not empty
*/
static inline void tcp_dequeue_last_in_send_buf(tcp_pcb_t *pcb)
{
    pbuf_t *pbuf;

    pbuf = dlist_last(&pcb->send_buf_list, pbuf_t, node);
    dlist_del(&pbuf->node);
    pbuf_put_last(pbuf);
}

/*
    caller MUST ensure send_buf_list is not empty
*/
static inline void tcp_dequeue_data_in_send_buf(tcp_pcb_t *pcb)
{
    pbuf_t *p, *p2;

    dlist_for_each_node_safe(p, p2, &pcb->send_buf_list, node) {
        lune_assert(PBUF_GET_PAYLOAD_LEN(p) > 0);
        pcb->send_lbb -= PBUF_GET_PAYLOAD_LEN(p);
        dlist_del(&p->node);
        pbuf_put_last(p);
    }
}

static inline int tcp_abort_new_conn_v4(ip_t *ipp,
    lune_ip_addr_t *dst_ip,
    unsigned short src_port,
    unsigned short dst_port,
    unsigned int ack_no)
{
    return tcp_send_ctrl_pkt(ipp, dst_ip, src_port, dst_port,
        TCP_GET_NEW_SEQ_NO(), ack_no, TCP_FLAG_RST_ACK, 0);
}

static inline void tcp_init_state(tcp_pcb_t *pcb, tcp_state_en init_state)
{
    if (likely(NULL != pcb->ifp)) {
        ++*(((unsigned int *)&(((net_if_t *)pcb->ifp)->tcp_stats.state_stats)) + (unsigned int)init_state);
    }
    pcb->state = init_state;
}

static void tcp_stop_keep_alive(tcp_pcb_t *pcb, socket_x_t *sk);

static inline void tcp_update_state(tcp_pcb_t *pcb, tcp_state_en new_state)
{
    if (likely(NULL != pcb->ifp)) {
        --*(((unsigned int *)&(((net_if_t *)pcb->ifp)->tcp_stats.state_stats)) + (unsigned int)pcb->state);
        ++*(((unsigned int *)&(((net_if_t *)pcb->ifp)->tcp_stats.state_stats)) + (unsigned int)new_state);
    }

    if (TCP_KEEP_ALIVE_ON(pcb)
        && TCP_EST == pcb->state) {
        if (LUNE_TIMER_IS_ADDED(pcb->keep_alive_tmr)) {
            tcp_stop_keep_alive(pcb, SOCKET_X_GET_SK_BY_PCB(pcb));
        } else {
            /* edge case such as connection closed in connect/accept callback function */
        }
        TCP_KEEP_ALIVE_TURN_OFF(pcb);
    }

    pcb->state = new_state;
}

static inline void tcp_fini_state(tcp_pcb_t *pcb)
{
    lune_assert(TCP_CLOSED != pcb->state);
    if (likely(NULL != pcb->ifp)) {
        --*(((unsigned int *)&(((net_if_t *)pcb->ifp)->tcp_stats.state_stats)) + (unsigned int)pcb->state);
    }

    if (TCP_KEEP_ALIVE_ON(pcb)
        && TCP_EST == pcb->state) {
        lune_assert(LUNE_TIMER_IS_ADDED(pcb->keep_alive_tmr));
        tcp_stop_keep_alive(pcb, SOCKET_X_GET_SK_BY_PCB(pcb));
        TCP_KEEP_ALIVE_TURN_OFF(pcb);
    }

    pcb->state = TCP_CLOSED;
}

static inline void tcp_listen_init_state(tcp_listen_pcb_t *pcb, tcp_state_en init_state)
{
    if (likely(NULL != pcb->ifp)) {
        ++*(((unsigned int *)&(((net_if_t *)pcb->ifp)->tcp_stats.state_stats)) + (unsigned int)init_state);
    }

    pcb->state = init_state;
}

static inline void tcp_listen_fini_state(tcp_listen_pcb_t *pcb)
{
    if (likely(NULL != pcb->ifp)) {
        --*(((unsigned int *)&(((net_if_t *)pcb->ifp)->tcp_stats.state_stats)) + (unsigned int)pcb->state);
    }

    pcb->state = TCP_CLOSED;
}

static inline socket_x_t *tcp_create_passive_socket(lune_ip_addr_t *dst_ip,
    lune_tcp_hdr_t *tcph,
    socket_t *listen_sk)
{
    socket_x_t *sk;
    tcp_pcb_t *pcb;
    tcp_listen_pcb_t *listen_pcb = &listen_sk->pcb.tcp_listen;

    if (NULL == (sk = (socket_x_t *)socket_create(LUNE_SOCKET_TCP))) {
        return NULL;
    }

    pcb = &sk->pcb.tcp;

    dlist_add_tail(&pcb->node, &listen_pcb->backlog_list);
    listen_pcb->backlog_cnt++;

    pcb->ipp = listen_pcb->ipp;
    ip_hold(pcb->ipp);

    pcb->ifp = listen_pcb->ifp;
    if (likely(NULL != pcb->ifp)) {
        net_if_hold(pcb->ifp);
    }

    pcb->dst_ip = *dst_ip;
    pcb->src_port = tcph->dst_port;
    pcb->dst_port = tcph->src_port;

    pcb->flags = listen_pcb->flags;

    pcb->mss = listen_pcb->init_mss;
    pcb->cwnd = listen_pcb->init_cwnd;
    pcb->ss_thresh = listen_pcb->init_ss_thresh;

    pcb->recv_nxt = tcph->seq_no + 1;
    if (TCP_ZERO_WIN_ON(listen_pcb)) {
        pcb->recv_wnd = 0;
    }

    if (TCP_KEEP_ALIVE_ON(pcb)) {
        memcpy(&pcb->keep_alive, &listen_pcb->keep_alive,
            sizeof(lune_tcp_socket_keep_alive_param_t));
        pcb->keep_alive_probes = pcb->keep_alive.probes;
    }

    pcb->delack_intvl = listen_pcb->delack_intvl;

    /* state has been initialized in socket_create() */
    tcp_init_state(pcb, TCP_SYNR);

    pcb->setup_start_jiffies = TIMER_GET_CURRENT_JIFFIES();

    memcpy(&pcb->cb, &listen_pcb->cb, sizeof(lune_tcp_socket_callback_t));

    pcb->listen_sk = listen_sk;
    socket_hold(listen_sk);

    sk->rsvd_hdr_len = listen_sk->rsvd_hdr_len;

    return sk;
}

static inline void tcp_delete_passive_socket(socket_x_t *sk)
{
    tcp_pcb_t *pcb = &sk->pcb.tcp;
    tcp_listen_pcb_t *listen_pcb = &pcb->listen_sk->pcb.tcp_listen;

    lune_assert(!LUNE_TIMER_IS_ADDED(pcb->delack_tmr));
    lune_assert(!LUNE_TIMER_IS_ADDED(pcb->time_wait_tmr));
    lune_assert(dlist_node_is_added(&pcb->node));

    if (LUNE_TIMER_IS_ADDED(pcb->retrans_tmr)) {
        timer_del_timer(&pcb->retrans_tmr);
        socket_put(sk);
    }

    tcp_free_all_pbuf(pcb);

    dlist_del_init(&pcb->node);
    listen_pcb->backlog_cnt--;
    socket_put(pcb->listen_sk);
    pcb->listen_sk = NULL;

    ip_put(pcb->ipp);
    pcb->ipp = NULL;

    if (likely(NULL != pcb->ifp)) {
        net_if_put(pcb->ifp);
        pcb->ifp = NULL;
    }

    lune_assert(!socket_close((socket_t *)sk));
}

static inline int tcp_output_ctrl(socket_x_t *sk)
{
    tcp_pcb_t *pcb = &sk->pcb.tcp;
    pbuf_t *pbuf;
    unsigned long long expires;
    int err;

    lune_assert(dlist_one_node_only(&pcb->send_buf_list));

    pbuf = dlist_first(&pcb->send_buf_list, pbuf_t, node);
    if (unlikely(0 != (err = ip_output_nofrag(pcb->ipp, &pcb->dst_ip, LUNE_IP_PROTO_TCP, pbuf)))) {
        return err;
    }

    dlist_del(&pbuf->node);

    dlist_add_tail(&pbuf->node, &pcb->unack_buf_list);
    pbuf_reset_pbuf(pbuf, (unsigned char *)pbuf->tcp.hdr, (unsigned char *)pbuf->tcp.hdr);

    expires = pbuf->jiffies + TCP_GET_RETRANS_INTVL(pbuf->tcp.retrans_times++);
    if (!LUNE_TIMER_IS_ADDED(pcb->retrans_tmr)) {
        socket_hold(sk);
        timer_add_timer(&pcb->retrans_tmr, TIMER_GET_TIME_EXPIRE(expires));
    } else if (TIMER_TIME_BEFORE(expires, TIMER_GET_TIMER_JIFFIES(pcb->retrans_tmr))) {
        timer_mod_timer(&pcb->retrans_tmr, TIMER_GET_TIME_EXPIRE(expires));
    } else {
        /* current retransmit timer is good to go */
    }

    if ((pbuf->tcp.hdr->flags & TCP_FLAG_ACK)
        && LUNE_TIMER_IS_ADDED(pcb->delack_tmr)) {
        timer_del_timer(&pcb->delack_tmr);
        socket_put(sk);
    }

    return 0;
}

static inline int tcp_output_data(socket_x_t *sk)
{
    tcp_pcb_t *pcb = &sk->pcb.tcp;
    pbuf_t *p, *p2;
    unsigned long long t, expires = (unsigned long long)-1;
    int sent_len = 0, len;

    lune_assert(!dlist_is_empty(&pcb->send_buf_list));

    dlist_for_each_node_safe(p, p2, &pcb->send_buf_list, node) {
        len = PBUF_GET_PAYLOAD_LEN(p);

        if (unlikely(0 != ip_output_nofrag(pcb->ipp, &pcb->dst_ip, LUNE_IP_PROTO_TCP, p))) {
            break;
        }

        sent_len += len;

        dlist_del(&p->node);

        t = p->jiffies + TCP_GET_RETRANS_INTVL(p->tcp.retrans_times++);
        if ((unsigned long long)-1 == expires
            || TIMER_TIME_BEFORE(t, expires)) {
            expires = t;
        }

        dlist_add_tail(&p->node, &pcb->unack_buf_list);
        pbuf_reset_pbuf(p, (unsigned char *)p->tcp.hdr, (unsigned char *)p->tcp.hdr);
    }

    if (likely((unsigned long long)-1 != expires)) {
        TCP_ACK_SENT_SET_FLAG(pcb);

        if (!LUNE_TIMER_IS_ADDED(pcb->retrans_tmr)) {
            socket_hold(sk);
            timer_add_timer(&pcb->retrans_tmr, TIMER_GET_TIME_EXPIRE(expires));
        } else if (TIMER_TIME_BEFORE(expires, TIMER_GET_TIMER_JIFFIES(pcb->retrans_tmr))) {
            timer_mod_timer(&pcb->retrans_tmr, TIMER_GET_TIME_EXPIRE(expires));
        } else {
            /* current retransmit timer is good to go */
        }

        if (sent_len > 0) {
            if (LUNE_TIMER_IS_ADDED(pcb->delack_tmr)) {
                timer_del_timer(&pcb->delack_tmr);
                socket_put(sk);
            } else if (!TCP_EST_FASTACK_ON(pcb)) {
                /*
                    data being sent in connect callback function (the only
                    case in which this branch is reached), trigger piggybacking
                    ACK of 3-way handshake on data by turning on FASTACK so a
                    single ACK won't be sent after callback function
                */
                TCP_EST_FASTACK_TURN_ON(pcb);
            }
        }
    } else {
        lune_assert(0 == sent_len);
    }

    return sent_len;
}

static inline int tcp_output_retrans(socket_x_t *sk, unsigned long long expires)
{
    tcp_pcb_t *pcb = &sk->pcb.tcp;
    pbuf_t *p, *p2;
    unsigned long long t;
    int err, ack_flag = 0;

    lune_assert(!dlist_is_empty(&pcb->send_buf_list));

    dlist_for_each_node_safe(p, p2, &pcb->send_buf_list, node) {
        if (unlikely(0 != (err = ip_output_nofrag(pcb->ipp, &pcb->dst_ip, LUNE_IP_PROTO_TCP, p)))) {
            /* simply return error and socket will be destroyed */
            return err;
        }

        dlist_del(&p->node);

        t = p->jiffies + TCP_GET_RETRANS_INTVL(p->tcp.retrans_times++);
        if ((unsigned long)-1 == expires
            || TIMER_TIME_BEFORE(t, expires)) {
            expires = t;
        }

        dlist_add_tail(&p->node, &pcb->unack_buf_list);
        pbuf_reset_pbuf(p, (unsigned char *)p->tcp.hdr, (unsigned char *)p->tcp.hdr);
        if (p->tcp.hdr->flags & TCP_FLAG_ACK) {
            ack_flag = 1;
        }
    }

    if ((unsigned long long)-1 != expires) {
        socket_hold(sk);
        if (likely(TIMER_TIME_AFTER_NOW(expires))) {
            timer_add_timer(&pcb->retrans_tmr, TIMER_GET_TIME_EXPIRE(expires));
        } else {
            timer_add_timer(&pcb->retrans_tmr, 1);
        }
    }

    if (ack_flag && LUNE_TIMER_IS_ADDED(pcb->delack_tmr)) {
        timer_del_timer(&pcb->delack_tmr);
        socket_put(sk);
    }

    return 0;
}

static inline int tcp_process_opt(tcp_pcb_t *pcb, lune_tcp_hdr_t *tcph, unsigned short opt_len)
{
    tcp_opt_hdr_t *tcpoh;
    unsigned short opt_offset, mss;

    if (0 == opt_len) {
        return 0;
    }

    tcpoh = (tcp_opt_hdr_t *)((unsigned char *)tcph + LUNE_TCP_HDR_LEN);
    opt_offset = 0;
    while (opt_offset < opt_len) {
        switch (tcpoh->type) {
        case TCP_OPT_EOL:
            goto DONE;
        case TCP_OPT_NOP:
            opt_offset += TCP_OPT_MIN_HDR_LEN;
            tcpoh = (tcp_opt_hdr_t *)((unsigned char *)tcpoh + TCP_OPT_MIN_HDR_LEN);
            continue;
        case TCP_OPT_MSS:
            if (unlikely(TCP_OPT_MSS_LEN != tcpoh->len)) {
                /* malformed tcp option */
                return ERR_SET_ERR(LUNE_ERR_TCP_UNEXPECTED_PKT);
            }

            opt_offset += TCP_OPT_MSS_LEN;
            mss = lune_ntohs(*(unsigned short *)((unsigned char *)tcpoh + TCP_OPT_HDR_LEN));
            if (pcb->mss > mss) {
                /* mss not exceed max mss */
                pcb->mss = mss;
                pcb->cwnd = mss * TCP_INIT_CWND_SEG_NUM;
                pcb->ss_thresh = mss * TCP_INIT_SS_THRESH_SEG_NUM;
            }

            tcpoh = (tcp_opt_hdr_t *)((unsigned char *)tcpoh + TCP_OPT_MSS_LEN);
            continue;
        case TCP_OPT_WS:
            if (unlikely(TCP_OPT_WS_LEN != tcpoh->len)) {
                /* malformed tcp option */
                return ERR_SET_ERR(LUNE_ERR_TCP_UNEXPECTED_PKT);
            }

            /* TODO: support window scale */
            opt_offset += TCP_OPT_WS_LEN;
            tcpoh = (tcp_opt_hdr_t *)((unsigned char *)tcpoh + TCP_OPT_WS_LEN);
            continue;
        case TCP_OPT_SACK_PERM:
            if (unlikely(TCP_OPT_SACK_PERM_LEN != tcpoh->len)) {
                /* malformed tcp option */
                return ERR_SET_ERR(LUNE_ERR_TCP_UNEXPECTED_PKT);
            }

            /* TODO: support sack permitted */
            opt_offset += TCP_OPT_SACK_PERM_LEN;
            tcpoh = (tcp_opt_hdr_t *)((unsigned char *)tcpoh + TCP_OPT_SACK_PERM_LEN);
            continue;
        default:
            lune_log(LUNE_INFO, "received flag %x with unsupported option at state %s "
                "on tcp connection %s",
                tcph->flags,
                TCP_GET_STATE_STR(pcb->state),
                tcp_print_pcb_4tuple(pcb));
            /* skip all remaining options */
            goto DONE;
        }
    }

DONE:
    return 0;
}

static inline int tcp_process_new_syn(ip_t *ipp, lune_ip_addr_t *dst_ip, lune_tcp_hdr_t *tcph)
{
    tcp_pcb_t *new_pcb;
    tcp_listen_pcb_t *listen_pcb;
    socket_t *listen_sk, psd_sk;
    socket_x_t *new_sk;
    int err;

    if (NULL != ipp->tcp_listen_sk) {
        switch (((socket_t *)ipp->tcp_listen_sk)->type) {
        case LUNE_SOCKET_TCP_LISTEN:
            if (ipp == ((socket_t *)ipp->tcp_listen_sk)->pcb.tcp_listen.ipp
                && tcph->dst_port == ((socket_t *)ipp->tcp_listen_sk)->pcb.tcp_listen.port) {
                listen_sk = (socket_t *)ipp->tcp_listen_sk;
                goto LISTEN_SOCKET_FOUND;
            }
            break;
        case LUNE_SOCKET_TCP_BATCH_LISTEN:
            if (ipp == ((socket_t *)ipp->tcp_listen_sk)->pcb.tcp_listen.ipp
                && tcph->dst_port >= ((socket_t *)ipp->tcp_listen_sk)->pcb.tcp_listen.port
                && tcph->dst_port <= ((socket_t *)ipp->tcp_listen_sk)->pcb.tcp_listen.end_port) {
                listen_sk = (socket_t *)ipp->tcp_listen_sk;
                goto LISTEN_SOCKET_FOUND;
            }
            break;
        default:
            lune_assert(LUNE_SOCKET_TCP_PEER_LISTEN == ((socket_t *)ipp->tcp_listen_sk)->type);
            break;
        }
    }

    psd_sk.pcb.tcp_listen.ipp = ipp;
    psd_sk.pcb.tcp_listen.port = tcph->dst_port;
    if (s_tcp_batch_listen_socket_cnt > 0) {
        psd_sk.type = LUNE_SOCKET_TCP_BATCH_LISTEN;
        psd_sk.ops = &g_socket_ops_tcp_batch_listen;
        psd_sk.pcb.tcp_listen.end_port = 0;
        if (NULL != (listen_sk = socket_listen_socket_find(&psd_sk))) {
            if (NULL != ipp->tcp_listen_sk) {
                socket_put(ipp->tcp_listen_sk);
            }
            ipp->tcp_listen_sk = (void *)listen_sk;
            socket_hold(listen_sk);
            goto LISTEN_SOCKET_FOUND;
        }
    }

    if (s_tcp_peer_listen_socket_cnt > 0) {
        psd_sk.type = LUNE_SOCKET_TCP_PEER_LISTEN;
        psd_sk.ops = &g_socket_ops_tcp_peer_listen;
        LUNE_IP_CPY(&psd_sk.pcb.tcp_listen.peer_addr, dst_ip);
        if (NULL != (listen_sk = socket_listen_socket_find(&psd_sk))) {
            if (NULL != ipp->tcp_listen_sk) {
                socket_put(ipp->tcp_listen_sk);
            }
            ipp->tcp_listen_sk = (void *)listen_sk;
            socket_hold(listen_sk);
            goto LISTEN_SOCKET_FOUND;
        }
    }

    psd_sk.type = LUNE_SOCKET_TCP_LISTEN;
    psd_sk.ops = &g_socket_ops_tcp_listen;
    if (unlikely(NULL == (listen_sk = socket_listen_socket_find(&psd_sk)))) {
        /* socket is not listening */
        lune_log_once(LUNE_DBG, "received new connection request %s while no socket is listening",
            tcp_print_4tuple(ipp, dst_ip, tcph->dst_port, tcph->src_port));
        return tcp_abort_new_conn_v4(ipp, dst_ip,
            tcph->dst_port, tcph->src_port, tcph->seq_no);
    }

    if (NULL != ipp->tcp_listen_sk) {
        socket_put(ipp->tcp_listen_sk);
    }
    ipp->tcp_listen_sk = (void *)listen_sk;
    socket_hold(listen_sk);

LISTEN_SOCKET_FOUND:
    listen_pcb = &listen_sk->pcb.tcp_listen;
    if (unlikely(!TCP_LISTEN_IS_BACKLOG_UNLIMITED(listen_pcb)
        && listen_pcb->backlog <= listen_pcb->backlog_cnt)) {
        /*
            listening socket has reached backlog limit and has to
            reject new incoming connection request
        */
        lune_log(LUNE_DBG, "failed to accept new connection request %s"
            " due to listening socket backlog limit %d",
            tcp_print_4tuple(listen_pcb->ipp, dst_ip, tcph->dst_port, tcph->src_port),
            listen_pcb->backlog);
        return tcp_abort_new_conn_v4(ipp, dst_ip,
            tcph->dst_port, tcph->src_port, tcph->seq_no);
    }

    if (unlikely(0 == tcph->win_size)) {
        /* unexpected zero window case */
        lune_log(LUNE_DBG, "failed to accept new connection request %s"
            " due to unexpected zero window",
            tcp_print_4tuple(listen_pcb->ipp, dst_ip, tcph->dst_port, tcph->src_port),
            listen_pcb->backlog);
        return tcp_abort_new_conn_v4(ipp, dst_ip,
            tcph->dst_port, tcph->src_port, tcph->seq_no);
    }

    if (unlikely(NULL == (new_sk = tcp_create_passive_socket(dst_ip, tcph, listen_sk)))) {
        err = ERR_GET_LAST_ERR();
        lune_log(LUNE_WARN, "failed to allocate memory for new connection %s: %s",
            tcp_print_4tuple(ipp, dst_ip, tcph->dst_port, tcph->src_port),
            ERR_GET_ERR_STR(err));
        goto ERR_1;
    }

    new_pcb = &new_sk->pcb.tcp;
    if (unlikely(0 != (err = tcp_enqueue_ctrl(new_sk, TCP_FLAG_SYN_ACK)))) {
        lune_log(LUNE_INFO, "failed to enqueue tcp SYN+ACK at state %s on tcp connection %s: %s",
            TCP_GET_STATE_STR(new_pcb->state),
            tcp_print_pcb_4tuple(new_pcb), ERR_GET_ERR_STR(err));
        goto ERR_2;
    }

    /*
        option header should be processed after SYN+ACK enqueued so that local mss won't be
        overwritten by remote one
    */
    if (unlikely(0 != (err = tcp_process_opt(new_pcb,
        tcph, (unsigned short)TCP_GET_OPT_HDR_LEN(tcph))))) {
        lune_log(LUNE_INFO, "failed to process tcp option at state %s on tcp connection %s: %s",
            TCP_GET_STATE_STR(new_pcb->state),
            tcp_print_pcb_4tuple(new_pcb), ERR_GET_ERR_STR(err));
        goto ERR_2;
    }

    if (unlikely(0 != (err = tcp_output_ctrl(new_sk)))) {
        lune_log(LUNE_INFO, "failed to send tcp SYN+ACK at state %s on tcp connection %s: %s",
            TCP_GET_STATE_STR(new_pcb->state),
            tcp_print_pcb_4tuple(new_pcb), ERR_GET_ERR_STR(err));
        goto ERR_2;
    }

    if (unlikely(0 != (err = socket_insert(new_sk)))) {
        lune_log(LUNE_WARN, "failed to insert socket at state %s on tcp connection %s: %s",
            TCP_GET_STATE_STR(new_pcb->state),
            tcp_print_pcb_4tuple(new_pcb), ERR_GET_ERR_STR(err));
        goto ERR_2;
    }

    return 0;

ERR_2:
    tcp_delete_passive_socket(new_sk);

ERR_1:
    return err;
}

/* tear down socket due to error */
static inline void tcp_teardown_socket(socket_x_t *sk, int err)
{
    tcp_pcb_t *pcb = &sk->pcb.tcp;
    tcp_state_en state;

    lune_assert(0 != err);

    if (TCP_SYNR == pcb->state) {
        tcp_fini_state(pcb);
        lune_assert(!socket_remove(sk));
        tcp_delete_passive_socket(sk);
        return;
    }

    if (likely(NULL != pcb->ifp)) {
        if (TCP_SYNS == pcb->state) {
            NET_IF_TCP_INC_ABORTED_CONN(pcb->ifp);
        } else {
            NET_IF_TCP_INC_FAILED_CONN(pcb->ifp);
            NET_IF_TCP_DEC_CONCURRENT_CONN(pcb->ifp);
        }
    }

    if (LUNE_TIMER_IS_ADDED(pcb->delack_tmr)) {
        timer_del_timer(&pcb->delack_tmr);
        socket_put(sk);
    }

    if (LUNE_TIMER_IS_ADDED(pcb->retrans_tmr)) {
        timer_del_timer(&pcb->retrans_tmr);
        socket_put(sk);
    }

    /* either time_wait_tmr or delay_rst_tmr */
    if (LUNE_TIMER_IS_ADDED(pcb->time_wait_tmr)) {
        timer_del_timer(&pcb->time_wait_tmr);
        socket_put(sk);
    }

    if (LUNE_TIMER_IS_ADDED(pcb->keep_alive_tmr)) {
        timer_del_timer(&pcb->keep_alive_tmr);
        socket_put(sk);
    }

    if (TCP_EST == pcb->state
        && likely(NULL != pcb->ifp)) {
        lune_assert(0 != pcb->est_start_jiffies);
        net_if_tcp_add_session_duration(pcb->ifp, TIMER_GET_CURRENT_JIFFIES() - pcb->est_start_jiffies);
    }
    state = pcb->state;
    tcp_fini_state(pcb);

    tcp_free_all_pbuf(pcb);
    if (!SOCKET_IS_CLOSED(sk)) {
        /* close socket so it's not accessible in callback error() */
        lune_assert(!socket_close(sk));
    }

    if (TCP_SYNR != state
        && TCP_TWAIT != state
        && NULL != pcb->cb.error) {
        pcb->cb.error(pcb->cb.data, err);
    }

    /* remove socket after callback error() so that it's not freed till now */
    if (socket_is_added(sk)) {
        lune_assert(!socket_remove(sk));
    }

    /* must be called after socket_remove() */
    if (NULL != pcb->ipp) {
        ip_put(pcb->ipp);
        pcb->ipp = NULL;
        if (likely(NULL != pcb->ifp)) {
            net_if_put(pcb->ifp);
            pcb->ifp = NULL;
        }
    }
}

static inline int tcp_close_socket(socket_x_t *sk, unsigned int type)
{
    tcp_pcb_t *pcb = &sk->pcb.tcp;
    tcp_state_en state;

    if (LUNE_TIMER_IS_ADDED(pcb->retrans_tmr)) {
        timer_del_timer(&pcb->retrans_tmr);
        socket_put(sk);
    }

    if (LUNE_TIMER_IS_ADDED(pcb->delack_tmr)) {
        timer_del_timer(&pcb->delack_tmr);
        socket_put(sk);
    }

    /* either time_wait_tmr or delay_rst_tmr */
    if (LUNE_TIMER_IS_ADDED(pcb->time_wait_tmr)) {
        timer_del_timer(&pcb->time_wait_tmr);
        socket_put(sk);
    }

    if (TCP_SYNR == pcb->state) {
        tcp_fini_state(pcb);
        lune_assert(!socket_remove(sk));
        tcp_delete_passive_socket(sk);
        return 0;
    }

    if (likely(NULL != pcb->ifp)) {
        if (TCP_SYNS == pcb->state) {
            NET_IF_TCP_INC_ABORTED_CONN(pcb->ifp);
        } else {
            if (TCP_EST == pcb->state
                && likely(NULL != pcb->ifp)) {
                lune_assert(0 != pcb->est_start_jiffies);
                net_if_tcp_add_session_duration(pcb->ifp, TIMER_GET_CURRENT_JIFFIES() - pcb->est_start_jiffies);
            }
            NET_IF_TCP_INC_CLOSED_CONN(pcb->ifp);
            NET_IF_TCP_DEC_CONCURRENT_CONN(pcb->ifp);
        }
    }
    state = pcb->state;
    tcp_fini_state(pcb);

    tcp_free_all_pbuf(pcb);
    if (!SOCKET_IS_CLOSED(sk)) {
        /* close socket so it's not accessible in callback close() */
        lune_assert(!socket_close(sk));
    }

    if (TCP_TWAIT != state
        && NULL != pcb->cb.close) {
        pcb->cb.close(pcb->cb.data, type);
    }

    /* remove socket after callback close() so that it's not freed till now */
    lune_assert(!socket_remove(sk));

    /* must be called after socket_remove() */
    ip_put(pcb->ipp);
    pcb->ipp = NULL;
    if (likely(NULL != pcb->ifp)) {
        net_if_put(pcb->ifp);
        pcb->ifp = NULL;
    }

    return 0;
}

static inline int tcp_update_unack_buf_list(socket_x_t *sk, lune_tcp_hdr_t *tcph)
{
    tcp_pcb_t *pcb = &sk->pcb.tcp;
    pbuf_t *p, *p2;
    unsigned int cnt, ack_data_len;

    cnt = 0, ack_data_len = 0;
    dlist_for_each_node_safe(p, p2, &pcb->unack_buf_list, node) {
        if (TCP_SEQ_GEQ(lune_ntohl(((lune_tcp_hdr_t *)PBUF_GET_HDR(p))->seq_no), tcph->ack_no)) {
            break;
        }

        cnt++;
        /* just notice that acknowledged data length may be zero if it's a control packet */
        ack_data_len += (PBUF_GET_PAYLOAD_LEN(p) - TCP_GET_HDR_LEN(PBUF_GET_HDR(p)));
        dlist_del(&p->node);
        pbuf_put(p);
    }

    if (0 == cnt) {
        /* acknowledge number is even greater than what has been sent */
        lune_log(LUNE_INFO, "received ACK is greater than expected at state %s"
            " on tcp connection %s",
            TCP_GET_STATE_STR(pcb->state),
            tcp_print_pcb_4tuple(pcb));
        return ERR_SET_ERR(LUNE_ERR_TCP_UNEXPECTED_PKT);
    }

    lune_assert(LUNE_TIMER_IS_ADDED(pcb->retrans_tmr));

    if (TCP_EST == pcb->state) {
        /*
            should we do congestion control at TCP_CLWAIT state?
        */
        if (pcb->cwnd < pcb->ss_thresh) {
            if ((unsigned int)(pcb->cwnd + ack_data_len) >= (unsigned int)pcb->ss_thresh) {
                pcb->cwnd = pcb->ss_thresh;
            } else {
                pcb->cwnd = pcb->cwnd + ack_data_len;
            }
        } else {
            if (pcb->cwnd > (TCP_MAX_CWND_SIZE - pcb->mss)) {
                pcb->cwnd = TCP_MAX_CWND_SIZE;
            } else {
                pcb->cwnd += pcb->mss;
            }
        }
    }

    if (dlist_is_empty(&pcb->unack_buf_list)) {
        timer_del_timer(&pcb->retrans_tmr);
        socket_put(sk);
    } else {
        /* retransmit timer update will be handled in tcp_retrans_tmr_func() */
    }

    pcb->last_ack = tcph->ack_no;

    return 0;
}

/*
    send ACK ASAP (but not right away)
*/
static inline void tcp_send_ack_fast(socket_x_t *sk)
{
    tcp_pcb_t *pcb = &sk->pcb.tcp;

    if (LUNE_TIMER_IS_ADDED(pcb->delack_tmr)) {
        timer_mod_timer(&pcb->delack_tmr, 1);
    } else {
        socket_hold(sk);
        timer_add_timer(&pcb->delack_tmr, 1);
    }
}

static inline int tcp_send_ack(socket_x_t *sk)
{
    tcp_pcb_t *pcb = &sk->pcb.tcp;

    if (LUNE_TIMER_IS_ADDED(pcb->delack_tmr)) {
        timer_mod_timer(&pcb->delack_tmr, 1);
        return 0;
    }

    if (TCP_DELACK_ON(pcb)) {
        socket_hold(sk);
        timer_add_timer(&pcb->delack_tmr, pcb->delack_intvl);
        return 0;
    }

    socket_hold(sk);
    timer_add_timer(&pcb->delack_tmr, 1);
    return 0;
}

/*
    send ACK right away
*/
static inline int tcp_send_ack_now(socket_x_t *sk)
{
    tcp_pcb_t *pcb = &sk->pcb.tcp;

    if (LUNE_TIMER_IS_ADDED(pcb->delack_tmr)) {
        timer_del_timer(&pcb->delack_tmr);
        socket_put(sk);
    }

    return tcp_send_ctrl_pkt(pcb->ipp, &pcb->dst_ip, pcb->src_port,
        pcb->dst_port, pcb->send_lbb, pcb->recv_nxt, TCP_FLAG_ACK, pcb->recv_wnd);
}

static inline int tcp_send_rst_ack(tcp_pcb_t *pcb)
{
    return tcp_send_ctrl_pkt(pcb->ipp, &pcb->dst_ip, pcb->src_port, pcb->dst_port,
        pcb->last_ack, pcb->recv_nxt, TCP_FLAG_RST_ACK, 0);
}

static inline int tcp_send_keep_alive_ack(tcp_pcb_t *pcb)
{
    return tcp_send_ctrl_pkt(pcb->ipp, &pcb->dst_ip, pcb->src_port, pcb->dst_port,
        pcb->last_ack - 1, pcb->recv_nxt, TCP_FLAG_ACK, pcb->recv_wnd);
}

static void tcp_retrans_tmr_func(socket_x_t *sk)
{
    tcp_pcb_t *pcb = &sk->pcb.tcp;
    unsigned short eff_wnd;
    pbuf_t *p, *p2, *p3;
    unsigned long long t, expires = (unsigned long long)-1;
    static __thread int last_err = 0;
    int err;

    lune_assert(TCP_CLOSED != pcb->state && TCP_TWAIT != pcb->state);
    lune_assert(!dlist_is_empty(&pcb->unack_buf_list));
    lune_assert(dlist_is_empty(&pcb->send_buf_list));
    lune_assert(!LUNE_TIMER_IS_ADDED(pcb->retrans_tmr));

    dlist_for_each_node_safe(p, p2, &pcb->unack_buf_list, node) {
        if (p->tcp.retrans_times > TCP_RETRANS_TIMES) {
            lune_log_once(LUNE_INFO, "hit maximum retransmit times at state %s"
                " on tcp connection %s",
                TCP_GET_STATE_STR(pcb->state),
                tcp_print_pcb_4tuple(pcb));

            if (0 != (err = tcp_send_rst_ack(pcb))
                && -LUNE_ERR_NET_IF_SEND_FAILED != err) {
                lune_log(LUNE_INFO, "failed to send RST at state %s on tcp "
                    "connection %s: %s",
                    TCP_GET_STATE_STR(pcb->state),
                    tcp_print_pcb_4tuple(pcb),
                    ERR_GET_LAST_ERR_STR());
            }

            err = ERR_SET_ERR(LUNE_ERR_MAX_RETRIES);
            goto ERR_CLOSE;
        }

        if (unlikely(!pbuf_is_last_ref(p))) {
            /* p still in use somewhere else */
            if (NULL == (p3 = pbuf_dup_pbuf(p))) {
                lune_log(LUNE_INFO, "failed to duplicate pbuf at state %s"
                    " on tcp connection %s: %s",
                    TCP_GET_STATE_STR(pcb->state),
                    tcp_print_pcb_4tuple(pcb),
                    ERR_GET_LAST_ERR_STR());
                err = ERR_GET_LAST_ERR();
                goto ERR_CLOSE;
            }

            dlist_replace(&p3->node, &p->node);
            pbuf_put(p);
            p = p3;
            pbuf_hold(p);
        }

        lune_assert(PBUF_GET_HDR(p) == (void *)p->tcp.hdr
            && PBUF_GET_PAYLOAD(p) == (void *)p->tcp.hdr);

        t = p->jiffies + TCP_GET_RETRANS_INTVL(p->tcp.retrans_times - 1);
        if (TIMER_TIME_AFTER_NOW(t)) {
            if ((unsigned long long)-1 == expires
                || TIMER_TIME_BEFORE(t, expires)) {
                expires = t;
            }
        } else {
            if (likely(TCP_FLAG_SYN != p->tcp.hdr->flags)) {
                p->tcp.hdr->ack_no = lune_htonl(pcb->recv_nxt);
            }

            dlist_del(&p->node);
            dlist_add_tail(&p->node, &pcb->send_buf_list);
        }
    }

    if (unlikely(dlist_is_empty(&pcb->send_buf_list))) {
        /* all the packets to be retransmitted now have been acknowledged, hop onto next */
        if (expires != (unsigned long long)-1) {
            lune_assert(TIMER_TIME_AFTER_TIMER(expires, pcb->retrans_tmr));
            timer_add_timer(&pcb->retrans_tmr, TIMER_GET_TIME_EXPIRE(expires));
            /* don't call socket_put() since the timer is renewed */
            return;
        }
    } else {
        /* update congestion control */
        eff_wnd = (pcb->send_wnd < pcb->cwnd) ? pcb->send_wnd : pcb->cwnd;
        pcb->ss_thresh = eff_wnd >> 1;
        if (pcb->ss_thresh < (pcb->mss * TCP_MIN_SS_THRESH_SEG_NUM)) {
            pcb->ss_thresh = pcb->mss * TCP_MIN_SS_THRESH_SEG_NUM;
        }
        pcb->cwnd = pcb->mss;

        if (0 != (err = tcp_output_retrans(sk, expires))) {
            if (last_err == err) {
                lune_log_once(LUNE_INFO, "failed to send packets at state %s on tcp connection %s: %s",
                    TCP_GET_STATE_STR(pcb->state),
                    tcp_print_pcb_4tuple(pcb),
                    ERR_GET_ERR_STR(err));
            } else {
                lune_log(LUNE_INFO, "failed to send packets at state %s on tcp connection %s: %s",
                    TCP_GET_STATE_STR(pcb->state),
                    tcp_print_pcb_4tuple(pcb),
                    ERR_GET_ERR_STR(err));
                last_err = err;
            }
            goto ERR_CLOSE;
        } else {
            last_err = 0;
        }

        if (LUNE_TIMER_IS_ADDED(pcb->delack_tmr)) {
            timer_del_timer(&pcb->delack_tmr);
            socket_put(sk);
        }
    }

    socket_put(sk);     /* paired with retransmit hold */
    return;

ERR_CLOSE:
    if (TCP_SYNR == pcb->state) {
        tcp_fini_state(pcb);
        lune_assert(!socket_remove(sk));
        tcp_delete_passive_socket(sk);
        socket_put(sk);     /* paired with retransmit hold */
        return;
    }

    tcp_teardown_socket(sk, err);

    socket_put(sk);     /* paired with retransmit hold */
}

static void tcp_delack_tmr_func(socket_x_t *sk)
{
    tcp_pcb_t *pcb = &sk->pcb.tcp;
    int err;

#ifdef LUNE_DEBUG
    lune_assert(TCP_CLOSED != pcb->state);
    lune_assert(!LUNE_TIMER_IS_ADDED(pcb->delack_tmr));
#endif

    if (0 != (err = tcp_send_ctrl_pkt(pcb->ipp, &pcb->dst_ip, pcb->src_port,
        pcb->dst_port, pcb->send_lbb, pcb->recv_nxt, TCP_FLAG_ACK, pcb->recv_wnd))) {
        lune_log(LUNE_INFO, "failed to send ACK at state %s on tcp connection %s: %s",
            TCP_GET_STATE_STR(pcb->state),
            tcp_print_pcb_4tuple(pcb),
            ERR_GET_LAST_ERR_STR());

        tcp_teardown_socket(sk, err);
    }

    socket_put(sk);     /* paired with delay-ACK hold */
}

/*
    only apply to delay reset close case
*/
static inline int tcp_socket_rst_close_now(socket_x_t *sk)
{
    tcp_pcb_t *pcb = &sk->pcb.tcp;
    int err;

    lune_assert(TCP_CLOSED != pcb->state);
    lune_assert(!LUNE_TIMER_IS_ADDED(pcb->delay_rst_tmr));

    if (0 != (err = tcp_send_rst_ack(pcb))) {
        lune_log(LUNE_INFO, "failed to send RST at state %s on tcp connection %s: %s",
            TCP_GET_STATE_STR(pcb->state),
            tcp_print_pcb_4tuple(pcb),
            ERR_GET_ERR_STR(err));
        tcp_teardown_socket(sk, err);
        return err;
    }

    if (LUNE_TIMER_IS_ADDED(pcb->retrans_tmr)) {
        timer_del_timer(&pcb->retrans_tmr);
        socket_put(sk);
    }

    if (LUNE_TIMER_IS_ADDED(pcb->delack_tmr)) {
        timer_del_timer(&pcb->delack_tmr);
        socket_put(sk);
    }

    if (likely(NULL != pcb->ifp)) {
        if (TCP_SYNS == pcb->state) {
            NET_IF_TCP_INC_ABORTED_CONN(pcb->ifp);
        } else {
            if (TCP_EST == pcb->state) {
                lune_assert(0 != pcb->est_start_jiffies);
                net_if_tcp_add_session_duration(pcb->ifp, TIMER_GET_CURRENT_JIFFIES() - pcb->est_start_jiffies);
            }
            NET_IF_TCP_INC_CLOSED_CONN(pcb->ifp);
            NET_IF_TCP_DEC_CONCURRENT_CONN(pcb->ifp);
        }
    }
    tcp_fini_state(pcb);

    tcp_free_all_pbuf(pcb);

    lune_assert(SOCKET_IS_CLOSED(sk));

    if (NULL != pcb->cb.close) {
        pcb->cb.close(pcb->cb.data, LUNE_TCP_SOCKET_CLOSE_RST);
    }

    lune_assert(!socket_remove(sk));

    /* must be called after socket_remove() */
    ip_put(pcb->ipp);
    pcb->ipp = NULL;
    if (likely(NULL != pcb->ifp)) {
        net_if_put(pcb->ifp);
        pcb->ifp = NULL;
    }

    return 0;
}

static void tcp_delay_rst_tmr_func(socket_x_t *sk)
{
    (void)tcp_socket_rst_close_now(sk);
    socket_put(sk);     /* paired with delay-RST hold */
}

static void tcp_time_wait_tmr_func(socket_x_t *sk)
{
    tcp_pcb_t *pcb = &sk->pcb.tcp;

    lune_assert(TCP_TWAIT == pcb->state);
    lune_assert(!LUNE_TIMER_IS_ADDED(pcb->retrans_tmr));
    lune_assert(!LUNE_TIMER_IS_ADDED(pcb->delack_tmr));
    lune_assert(!LUNE_TIMER_IS_ADDED(pcb->time_wait_tmr));

    tcp_fini_state(pcb);

    tcp_free_all_pbuf(pcb);

    lune_assert(!socket_remove(sk));

    /* must be called after socket_remove() */
    ip_put(pcb->ipp);
    pcb->ipp = NULL;
    if (likely(NULL != pcb->ifp)) {
        net_if_put(pcb->ifp);
        pcb->ifp = NULL;
    }

    socket_put(sk);     /* paired with time-wait hold */
}

static void tcp_keep_alive_tmr_func(socket_x_t *sk)
{
    int err;
    tcp_pcb_t *pcb = &sk->pcb.tcp;

    lune_assert(TCP_EST == pcb->state);

    if (0 == pcb->keep_alive_probes) {
        /* reach the end of the whole keep-alive period */
        tcp_process_keep_alive_timeout(pcb, sk);
        socket_put(sk);     /* paired with keep-alive hold */
        return;
    }

    if (0 != (err = tcp_send_keep_alive_ack(pcb))) {
        lune_log(LUNE_INFO, "failed to send keep-alive ACK on tcp connection %s: %s",
            tcp_print_pcb_4tuple(pcb), ERR_GET_ERR_STR(err));
        goto ERR_CLOSE;
    }

    pcb->keep_alive_probes--;
    timer_add_timer(&pcb->keep_alive_tmr, pcb->keep_alive.intvl * LUNE_TIME_SECOND);

    return;

ERR_CLOSE:
    tcp_teardown_socket(sk, err);
    socket_put(sk);     /* paired with keep-alive hold */
}

/*
    caller MUST guarantee keep-alive timer not added & interval not 0
*/
static int tcp_start_keep_alive(tcp_pcb_t *pcb, socket_x_t *sk)
{
    int err;

    socket_hold(sk);
    timer_init_timer(&pcb->keep_alive_tmr, LUNE_TIMER_ONCE,
        LUNE_TIMER_RES_DEFAULT, (lune_timer_func_t)tcp_keep_alive_tmr_func, sk);
    if (0 == pcb->keep_alive.time) {
        /* phase 2: probe & retransmit */
        lune_assert(pcb->keep_alive_probes == pcb->keep_alive.probes);
        if (0 != (err = tcp_send_keep_alive_ack(pcb))) {
            lune_log(LUNE_INFO, "failed to send keep-alive ACK on tcp connection %s: %s",
                tcp_print_pcb_4tuple(pcb), ERR_GET_ERR_STR(err));
            return err;
        }

        pcb->keep_alive_probes--;
        timer_add_timer(&pcb->keep_alive_tmr, pcb->keep_alive.intvl * LUNE_TIME_SECOND);
    } else {
        /* phase 1: idle before probe */
        timer_add_timer(&pcb->keep_alive_tmr, pcb->keep_alive.time * LUNE_TIME_SECOND);
    }

    return 0;
}

/*
    caller MUST guarantee keep-alive timer already added
*/
static void tcp_stop_keep_alive(tcp_pcb_t *pcb, socket_x_t *sk)
{
    pcb->keep_alive_probes = pcb->keep_alive.probes;
    timer_del_timer(&pcb->keep_alive_tmr);
    socket_put(sk);     /* paired with keep-alive hold */
}

/*
    caller MUST guarantee keep-alive timer already added & interval not 0
*/
static int tcp_restart_keep_alive(tcp_pcb_t *pcb)
{
    int err;

    if (0 == pcb->keep_alive.time) {
        /* phase 2: probe & retransmit */
        if (0 != (err = tcp_send_keep_alive_ack(pcb))) {
            lune_log(LUNE_INFO, "failed to send keep-alive ACK on tcp connection %s: %s",
                tcp_print_pcb_4tuple(pcb), ERR_GET_ERR_STR(err));
            return err;
        }

        pcb->keep_alive_probes = pcb->keep_alive.probes - 1;
        timer_mod_timer(&pcb->keep_alive_tmr, pcb->keep_alive.intvl * LUNE_TIME_SECOND);
    } else {
        /* phase 1: idle before probe */
        pcb->keep_alive_probes = pcb->keep_alive.probes;
        timer_mod_timer(&pcb->keep_alive_tmr, pcb->keep_alive.time * LUNE_TIME_SECOND);
    }

    return 0;
}

static inline void tcp_establish_passive_socket(socket_x_t *sk)
{
    tcp_pcb_t *pcb = &sk->pcb.tcp;
    tcp_listen_pcb_t *listen_pcb;

    lune_assert(NULL != pcb->listen_sk);

    listen_pcb = &pcb->listen_sk->pcb.tcp_listen;
    dlist_del_init(&pcb->node);
    listen_pcb->backlog_cnt--;
    socket_put(pcb->listen_sk);
    pcb->listen_sk = (socket_t *)-1;

    pcb->est_start_jiffies = TIMER_GET_CURRENT_JIFFIES();
    if (likely(NULL != pcb->ifp)) {
        NET_IF_TCP_INC_ESTABLISHED_CONN(pcb->ifp);
        NET_IF_TCP_INC_CONCURRENT_CONN(pcb->ifp);
        lune_assert(0 != pcb->setup_start_jiffies);
        net_if_tcp_add_setup_time(pcb->ifp, TIMER_GET_CURRENT_JIFFIES() - pcb->setup_start_jiffies);
    }
    tcp_update_state(pcb, TCP_EST);
}

#define TCP_UNORDERED_LIST_NOT_UPDATED  1
#define TCP_UNORDERED_LIST_UPDATED      2
#define TCP_UNORDERED_LIST_SOCKET_CLOSE 3
static inline int tcp_update_unordered_list(socket_x_t *sk)
{
    tcp_pcb_t *pcb = &sk->pcb.tcp;
    pbuf_t *p, *p2;
    int updated_flag = 0;

    dlist_for_each_node_safe(p, p2, &pcb->unordered_buf_list, node) {
        lune_tcp_hdr_t *tcph = (lune_tcp_hdr_t *)PBUF_GET_HDR(p);

        if (unlikely(TCP_SEQ_GT(pcb->recv_nxt, tcph->seq_no))) {
            return ERR_SET_ERR(LUNE_ERR_TCP_INTERNAL);
        }

        if (TCP_SEQ_LT(pcb->recv_nxt, tcph->seq_no)) {
            break;
        }

        updated_flag = 1;

        lune_assert(PBUF_GET_PAYLOAD_LEN(p) > 0);

        pcb->recv_nxt += PBUF_GET_PAYLOAD_LEN(p);

        if (likely(NULL != pcb->cb.recv)) {
            SOCKET_PUSH_CB_SK(sk);
            pcb->cb.recv(pcb->cb.data, PBUF_GET_PAYLOAD(p), PBUF_GET_PAYLOAD_LEN(p));
            SOCKET_POP_CB_SK();
            if (TCP_IS_SOCKET_CLOSED(sk)) {
                /* socket has been reset or quiet closed in callback recv() */
                return TCP_UNORDERED_LIST_SOCKET_CLOSE;
            }
        }

        dlist_del(&p->node);
        pbuf_free_pbuf(p);
    }

    return updated_flag ? TCP_UNORDERED_LIST_UPDATED : TCP_UNORDERED_LIST_NOT_UPDATED;
}

static inline int tcp_process_data(socket_x_t *sk, tcp_pcb_t *pcb, pbuf_t *pbuf)
{
    int err, ret;

    if (unlikely(TCP_EST_IS_ZERO_WIN(pcb))) {
        /* zero window of establishment has yet to be removed */
        err = ERR_SET_ERR(LUNE_ERR_TCP_UNEXPECTED_PKT);
        lune_log(LUNE_INFO, "received data while zero window of establishment not cleared"
            " at state %s on tcp connection %s",
            TCP_GET_STATE_STR(pcb->state),
            tcp_print_pcb_4tuple(pcb));
        goto ERR_RST_CLOSE;
    }

    TCP_ACK_SENT_CLEAR_FLAG(pcb);
    pcb->recv_nxt += PBUF_GET_PAYLOAD_LEN(pbuf);

    if (likely(NULL != pcb->cb.recv)) {
        SOCKET_PUSH_CB_SK(sk);
        pcb->cb.recv(pcb->cb.data, PBUF_GET_PAYLOAD(pbuf), PBUF_GET_PAYLOAD_LEN(pbuf));
        SOCKET_POP_CB_SK();
        if (TCP_IS_SOCKET_CLOSED(sk)) {
            /* socket has been reset or quiet closed in callback recv() */
            return 0;
        }
    }

    ret = tcp_update_unordered_list(sk);
    switch (ret) {
    case TCP_UNORDERED_LIST_NOT_UPDATED:
    case TCP_UNORDERED_LIST_UPDATED:
        if (!TCP_ACK_IS_SENT(pcb)) {
            if (0 != (err = tcp_send_ack(sk))) {
                lune_log(LUNE_INFO, "failed to send ACK at state %s on tcp connection %s: %s",
                    TCP_GET_STATE_STR(pcb->state),
                    tcp_print_pcb_4tuple(pcb),
                    ERR_GET_ERR_STR(err));
                goto ERR_CLOSE;
            }
        }
        break;
    case TCP_UNORDERED_LIST_SOCKET_CLOSE:
        return 0;
    case LUNE_ERR_TCP_INTERNAL:
        err = ret;
        lune_log(LUNE_INFO, "failed to update unordered list at state %s on tcp connection %s",
            TCP_GET_STATE_STR(pcb->state),
            tcp_print_pcb_4tuple(pcb));
        goto ERR_RST_CLOSE;
    default:
        /* the only case: falied to send ACK */
        err = ret;
        lune_log(LUNE_INFO, "failed to send ACK at state %s on tcp connection %s: %s",
            TCP_GET_STATE_STR(pcb->state),
            tcp_print_pcb_4tuple(pcb),
            ERR_GET_ERR_STR(err));
        goto ERR_CLOSE;
    }

    if (TCP_KEEP_ALIVE_ON(pcb)
        && TCP_EST == pcb->state) {
        if (0 != (err = tcp_restart_keep_alive(pcb))) {
            /* failed to reset keep-alive timer */
            goto ERR_CLOSE;
        }
    }

    return 0;

ERR_RST_CLOSE:
    if (0 != tcp_send_rst_ack(pcb)) {
        lune_log(LUNE_INFO, "failed to send RST at state %s on tcp connection %s: %s",
            TCP_GET_STATE_STR(pcb->state),
            tcp_print_pcb_4tuple(pcb),
            ERR_GET_LAST_ERR_STR());
    }

ERR_CLOSE:
    tcp_teardown_socket(sk, err);

    return err;
}

static inline int tcp_synr_process_ack(socket_x_t *sk, tcp_pcb_t *pcb, lune_tcp_hdr_t *tcph)
{
    pbuf_t *pbuf;

    if (unlikely(TCP_SEQ_NEQ(pcb->send_lbb, tcph->ack_no)
        || TCP_SEQ_NEQ(pcb->recv_nxt, tcph->seq_no))) {
        /* suspicious, close it */
        lune_log(LUNE_INFO, "received ACK with unexpected %s at state %s"
            " on tcp connection %s",
            TCP_SEQ_GT(pcb->send_lbb, tcph->ack_no) ? "ack_no" : "seq_no",
            TCP_GET_STATE_STR(pcb->state),
            tcp_print_pcb_4tuple(pcb));
        return ERR_SET_ERR(LUNE_ERR_TCP_UNEXPECTED_PKT);
    }

    lune_assert(0 == pcb->last_ack);

    lune_assert(!dlist_is_empty(&pcb->unack_buf_list));
    pbuf = dlist_first(&pcb->unack_buf_list, pbuf_t, node);
    dlist_del(&pbuf->node);
    pbuf_put(pbuf);
    lune_assert(dlist_is_empty(&pcb->unack_buf_list));

    lune_assert(LUNE_TIMER_IS_ADDED(pcb->retrans_tmr));
    timer_del_timer(&pcb->retrans_tmr);
    socket_put(sk);

    pcb->send_wnd = tcph->win_size;
    pcb->last_ack = tcph->ack_no;

    tcp_establish_passive_socket(sk);

    if (unlikely(0 == tcph->win_size)) {
        /* hold off triggering accept event until further non-zero-window ACK received */
        TCP_SET_EST_ZERO_WIN(pcb);
        return 0;
    }

    if (likely(NULL != pcb->cb.accept)) {
        lune_socket_addr_t addr;
        addr.port = pcb->dst_port;
        addr.addr = pcb->dst_ip;
        SOCKET_PUSH_CB_SK(sk);
        pcb->cb.accept(SOCKET_X_GET_ID(sk), &addr, &pcb->cb.data);
        SOCKET_POP_CB_SK();
        if (unlikely(TCP_IS_SOCKET_CLOSED(sk))) {
            if (TCP_CLOSE_TYPE_RST == TCP_GET_CLOSE_TYPE(pcb)) {
                /* socket has been reset or quiet closed in callback accept() */
                return 0;
            }
        }
    }

    if (TCP_KEEP_ALIVE_ON(pcb)) {
        lune_assert(!LUNE_TIMER_IS_ADDED(pcb->keep_alive_tmr));
        /* start keep-alive timer */
        return tcp_start_keep_alive(pcb, sk);
    }

    return 0;
}

static inline int tcp_process_ack(socket_x_t *sk, lune_tcp_hdr_t *tcph)
{
    tcp_pcb_t *pcb = &sk->pcb.tcp;
    int err;

    if (unlikely(TCP_SEQ_LT(pcb->send_lbb, tcph->ack_no))) {
        /* suspicious, close it */
        err = ERR_SET_ERR(LUNE_ERR_TCP_UNEXPECTED_PKT);
        lune_log(LUNE_INFO, "received ACK with unexpected ack_no at state %s"
            " on tcp connection %s",
            TCP_GET_STATE_STR(pcb->state),
            tcp_print_pcb_4tuple(pcb));
        goto ERR_RST_CLOSE;
    }

    if (TCP_SYNR == pcb->state) {
        if (0 != (err = tcp_synr_process_ack(sk, pcb, tcph))) {
            goto ERR_RST_CLOSE;
        }

        return 0;
    }

    lune_assert(TCP_SEQ_VAL(pcb->send_lbb, pcb->last_ack) >= 0);

    if (unlikely(TCP_SYNS == pcb->state)) {
        /* suspicious, close it */
        err = ERR_SET_ERR(LUNE_ERR_TCP_UNEXPECTED_PKT);
        lune_log(LUNE_INFO, "received ACK at state %s on tcp connection %s",
            TCP_GET_STATE_STR(pcb->state),
            tcp_print_pcb_4tuple(pcb));
        goto ERR_RST_CLOSE;
    } else if (unlikely(TCP_SEQ_GT(pcb->last_ack, tcph->ack_no))) {
        /*
            it barely happens... maybe just an unordered or
            retransmitted packet, simply toss it
        */
        return ERR_SET_ERR(LUNE_ERR_TCP_UNEXPECTED_PKT);
    } else if (TCP_SEQ_LT(pcb->last_ack, tcph->ack_no)) {
        if (0 != (err = tcp_update_unack_buf_list(sk, tcph))) {
            goto ERR_RST_CLOSE;
        }

        if (TCP_KEEP_ALIVE_ON(pcb)
            && TCP_EST == pcb->state) {
            if (0 != (err = tcp_restart_keep_alive(pcb))) {
                /* failed to reset keep-alive timer */
                goto ERR_CLOSE;
            }
        }
    }

    switch (pcb->state) {
    case TCP_EST:
        pcb->send_wnd = tcph->win_size;
        if (unlikely(TCP_EST_IS_ZERO_WIN(pcb))) {
            if (0 != tcph->win_size) {
                TCP_CLEAR_EST_ZERO_WIN(pcb);
                if (TCP_IS_SERVER_SOCKET(pcb)) {
                    if (likely(NULL != pcb->cb.accept)) {
                        lune_socket_addr_t addr;
                        addr.port = pcb->dst_port;
                        addr.addr = pcb->dst_ip;
                        SOCKET_PUSH_CB_SK(sk);
                        pcb->cb.accept(SOCKET_X_GET_ID(sk), &addr, &pcb->cb.data);
                        SOCKET_POP_CB_SK();
                        if (unlikely(TCP_IS_SOCKET_CLOSED(sk))) {
                            /* socket has been reset or quiet closed in callback accept() */
                            return 0;
                        }
                    }
                } else {
                    if (likely(NULL != pcb->cb.connect)) {
                        SOCKET_PUSH_CB_SK(sk);
                        pcb->cb.connect(pcb->cb.data);
                        SOCKET_POP_CB_SK();
                        if (unlikely(TCP_IS_SOCKET_CLOSED(sk))) {
                            /* socket has been reset or quiet closed in callback connect() */
                            return 0;
                        }
                    }
                }

                if (TCP_KEEP_ALIVE_ON(pcb)) {
                    lune_assert(!LUNE_TIMER_IS_ADDED(pcb->keep_alive_tmr));
                    /* start keep-alive timer */
                    if (0 != (err = tcp_start_keep_alive(pcb, sk))) {
                        goto ERR_CLOSE;
                    }

                    return 0;
                }
            }
        } else {
            if (likely(0 == TCP_SEQ_VAL(pcb->recv_nxt, tcph->seq_no))) {
                if (TCP_KEEP_ALIVE_ON(pcb)) {
                    lune_assert(LUNE_TIMER_IS_ADDED(pcb->keep_alive_tmr));
                    /* restart keep-alive timer */
                    if (0 != (err = tcp_restart_keep_alive(pcb))) {
                        goto ERR_CLOSE;
                    }
                }
            } else if (1 == TCP_SEQ_VAL(pcb->recv_nxt, tcph->seq_no)) {
                /* keep-alive ACK */
                if (TCP_KEEP_ALIVE_ON(pcb)) {
                    lune_assert(LUNE_TIMER_IS_ADDED(pcb->keep_alive_tmr));
                    /* restart keep-alive timer */
                    if (0 != (err = tcp_restart_keep_alive(pcb))) {
                        goto ERR_CLOSE;
                    }
                }

                tcp_send_ack_fast(sk);
            }
        }
        break;
    case TCP_FINWT2:
        /* do nothing */
        break;
    case TCP_FINWT1:
        if (unlikely(TCP_SEQ_GT(pcb->recv_nxt, tcph->seq_no))) {
            /* simply toss it */
            break;
        }

        /*
            for LT case: some data has been sent by the other
            peer following the last ACK which is probably lost
        */

        if (unlikely(TCP_SEQ_GT(pcb->send_lbb, tcph->ack_no))) {
            /* simply toss it and wait for the right ACK */
            break;
        }

        /* TCP_SEQ_EQ(pcb->send_lbb, tcph->ack_no) */
        tcp_update_state(pcb, TCP_FINWT2);
        break;
    case TCP_CLOSING:
        if (TCP_SEQ_EQ(pcb->recv_nxt, tcph->seq_no)
            && TCP_SEQ_EQ(pcb->send_lbb, tcph->ack_no)) {
            if (likely(NULL != pcb->ifp)) {
                lune_assert(0 != pcb->close_start_jiffies);
                net_if_tcp_add_close_time(pcb->ifp, TIMER_GET_CURRENT_JIFFIES() - pcb->close_start_jiffies);
                NET_IF_TCP_INC_CLOSED_CONN(pcb->ifp);
                NET_IF_TCP_DEC_CONCURRENT_CONN(pcb->ifp);
            }
            tcp_update_state(pcb, TCP_TWAIT);

            lune_assert(SOCKET_IS_CLOSED(sk));

            if (NULL != pcb->cb.close) {
                pcb->cb.close(pcb->cb.data, LUNE_TCP_SOCKET_CLOSE_NORMAL);
            }

            lune_assert(!LUNE_TIMER_IS_ADDED(pcb->time_wait_tmr));
            socket_hold(sk);
            timer_init_timer(&pcb->time_wait_tmr, LUNE_TIMER_ONCE,
                LUNE_TIMER_RES_HIGH, (lune_timer_func_t)tcp_time_wait_tmr_func, sk);
            timer_add_timer(&pcb->time_wait_tmr, TCP_DEFAULT_TWAIT_INTVL);

            break;
        }

        if (TCP_SEQ_LT(pcb->recv_nxt, tcph->seq_no)) {
            /* suspicious, close it */
            err = ERR_SET_ERR(LUNE_ERR_TCP_UNEXPECTED_PKT);
            lune_log(LUNE_INFO, "received ACK with unexpected seq_no at state %s"
                " on tcp connection %s",
                TCP_GET_STATE_STR(pcb->state),
                tcp_print_pcb_4tuple(pcb));
            goto ERR_RST_CLOSE;
        } else if (TCP_SEQ_GT(pcb->recv_nxt, tcph->seq_no)) {
            /* simply toss it */
            break;
        }

        /*
            TCP_SEQ_GT(pcb->send_lbb, tcph->ack_no)
            simply toss it and wait for the right ACK
        */
        break;
    case TCP_CLWAIT:
        pcb->send_wnd = tcph->win_size;
        /* fall through */
    case TCP_TWAIT:
        if (TCP_SEQ_LT(pcb->recv_nxt, tcph->seq_no)) {
            /* suspicious, close it */
            err = ERR_SET_ERR(LUNE_ERR_TCP_UNEXPECTED_PKT);
            lune_log(LUNE_INFO, "received ACK with unexpected seq_no at state %s"
                " on tcp connection %s",
                TCP_GET_STATE_STR(pcb->state),
                tcp_print_pcb_4tuple(pcb));
            goto ERR_RST_CLOSE;
        }
        break;
    case TCP_LASTACK:
        if (TCP_SEQ_NEQ(pcb->recv_nxt, tcph->seq_no)
            || TCP_SEQ_LT(pcb->send_lbb, tcph->ack_no)) {
            err = ERR_SET_ERR(LUNE_ERR_TCP_UNEXPECTED_PKT);
            lune_log(LUNE_INFO, "received ACK with unexpected ack_no and seq_no"
                " at state %s on tcp connection %s",
                TCP_GET_STATE_STR(pcb->state),
                tcp_print_pcb_4tuple(pcb));
            goto ERR_RST_CLOSE;
        }

        if (TCP_SEQ_GT(pcb->send_lbb, tcph->ack_no)) {
            /* skip old ACK */
            break;
        }

        /* TCP_SEQ_EQ(pcb->send_lbb, tcph->ack_no) */
        if (likely(NULL != pcb->ifp)) {
            NET_IF_TCP_INC_CLOSED_CONN(pcb->ifp);
            NET_IF_TCP_DEC_CONCURRENT_CONN(pcb->ifp);
            lune_assert(0 != pcb->close_start_jiffies);
            net_if_tcp_add_close_time(pcb->ifp, TIMER_GET_CURRENT_JIFFIES() - pcb->close_start_jiffies);
        }
        tcp_fini_state(pcb);

        if (LUNE_TIMER_IS_ADDED(pcb->delack_tmr)) {
            timer_del_timer(&pcb->delack_tmr);
            socket_put(sk);     /* paired with delack hold */
        }

        lune_assert(!LUNE_TIMER_IS_ADDED(pcb->time_wait_tmr));

        if (LUNE_TIMER_IS_ADDED(pcb->retrans_tmr)) {
            timer_del_timer(&pcb->retrans_tmr);
            socket_put(sk);
        }

        tcp_free_all_pbuf(pcb);

        lune_assert(SOCKET_IS_CLOSED(sk));

        if (NULL != pcb->cb.close) {
            pcb->cb.close(pcb->cb.data, LUNE_TCP_SOCKET_CLOSE_NORMAL);
        }

        lune_assert(!socket_remove(sk));

        /* must be called after socket_remove() */
        ip_put(pcb->ipp);
        pcb->ipp = NULL;
        if (likely(NULL != pcb->ifp)) {
            net_if_put(pcb->ifp);
            pcb->ifp = NULL;
        }

        break;
    default:
        err = ERR_SET_ERR(LUNE_ERR_TCP_UNEXPECTED_PKT);
        lune_log_once(LUNE_INFO, "received unexpected ACK at state %s on tcp connection %s",
            TCP_GET_STATE_STR(pcb->state),
            tcp_print_pcb_4tuple(pcb));
        goto ERR_RST_CLOSE;
    }

    return 0;

ERR_RST_CLOSE:
    if (0 != tcp_send_rst_ack(pcb)) {
        lune_log(LUNE_INFO, "failed to send RST at state %s on tcp connection %s: %s",
            TCP_GET_STATE_STR(pcb->state),
            tcp_print_pcb_4tuple(pcb),
            ERR_GET_LAST_ERR_STR());
    }

ERR_CLOSE:
    tcp_teardown_socket(sk, err);

    return err;
}

static inline void tcp_insert_unordered_list(tcp_pcb_t *pcb, pbuf_t *pbuf)
{
    pbuf_t *p, *p2;
    lune_tcp_hdr_t *tcph = (lune_tcp_hdr_t *)PBUF_GET_HDR(pbuf);

    tcph->src_port = lune_ntohs(tcph->src_port);
    tcph->dst_port = lune_ntohs(tcph->dst_port);
    tcph->win_size = lune_ntohs(tcph->win_size);
    tcph->seq_no = lune_ntohl(tcph->seq_no);
    tcph->ack_no = lune_ntohl(tcph->ack_no);

    dlist_for_each_node_safe(p, p2, &pcb->unordered_buf_list, node) {
        lune_tcp_hdr_t *tcph2 = (lune_tcp_hdr_t *)PBUF_GET_HDR(p);

        if (TCP_SEQ_LT(tcph->seq_no, tcph2->seq_no)) {
            dlist_add_tail(&pbuf->node, &p->node);
            return;
        } else if (TCP_SEQ_EQ(tcph->seq_no, tcph2->seq_no)) {
            dlist_replace(&pbuf->node, &p->node);
            pbuf_free_pbuf(p);
            return;
        }
    }

    dlist_add_tail(&pbuf->node, &pcb->unordered_buf_list);
}

static inline int tcp_process_data_ack(socket_x_t *sk, pbuf_t *pbuf, lune_tcp_hdr_t *tcph)
{
    tcp_pcb_t *pcb = &sk->pcb.tcp;
    int err;

    if (TCP_SYNR == pcb->state) {
        lune_assert(0 == pcb->last_ack);
        if (0 != (err = tcp_synr_process_ack(sk, pcb, tcph))) {
            goto ERR_RST_CLOSE;
        }

        /* data not accepted till zero window cleared */
        if (unlikely(TCP_EST_IS_ZERO_WIN(pcb))) {
            err = ERR_SET_ERR(LUNE_ERR_TCP_UNEXPECTED_PKT);
            lune_log(LUNE_INFO, "received data with unexpected zero window at state %s"
                " on tcp connection %s",
                TCP_GET_STATE_STR(pcb->state),
                tcp_print_pcb_4tuple(pcb));
            goto ERR_RST_CLOSE;
        }

        if (unlikely(TCP_IS_SOCKET_CLOSED(sk))) {
            /* socket has been reset or quiet closed in callback accept() in tcp_synr_process_ack() */
            return 0;
        }

        (void)pbuf_move_up(pbuf, TCP_GET_HDR_LEN(tcph));
        return tcp_process_data(sk, pcb, pbuf);
    }

    lune_assert(TCP_SEQ_VAL(pcb->send_lbb, pcb->last_ack) >= 0);

    if (unlikely(TCP_SEQ_LT(pcb->send_lbb, tcph->ack_no))) {
        /* suspicious, close it */
        err = ERR_SET_ERR(LUNE_ERR_TCP_UNEXPECTED_PKT);
        lune_log(LUNE_INFO, "received data with unexpected ack_no at state %s"
            " on tcp connection %s",
            TCP_GET_STATE_STR(pcb->state),
            tcp_print_pcb_4tuple(pcb));
        goto ERR_RST_CLOSE;
    }

    if (unlikely(TCP_SYNS == pcb->state)) {
        /* suspicious, close it */
        err = ERR_SET_ERR(LUNE_ERR_TCP_UNEXPECTED_PKT);
        lune_log(LUNE_INFO, "received data at state %s on tcp connection %s",
            TCP_GET_STATE_STR(pcb->state),
            tcp_print_pcb_4tuple(pcb));
        goto ERR_RST_CLOSE;
    } else if (unlikely(TCP_SEQ_GT(pcb->last_ack, tcph->ack_no))) {
        /*
            it barely happens... maybe just an unordered or
            retransmitted packet, simply toss it
        */
        return ERR_SET_ERR(LUNE_ERR_TCP_UNEXPECTED_PKT);
    } else if (TCP_SEQ_LT(pcb->last_ack, tcph->ack_no)) {
        if (0 != (err = tcp_update_unack_buf_list(sk, tcph))) {
            lune_log(LUNE_INFO, "received data with unexpected ack_no at state %s"
                " on tcp connection %s",
                TCP_GET_STATE_STR(pcb->state),
                tcp_print_pcb_4tuple(pcb));
            goto ERR_RST_CLOSE;
        }

        if (TCP_KEEP_ALIVE_ON(pcb)
            && TCP_EST == pcb->state) {
            if (0 != (err = tcp_restart_keep_alive(pcb))) {
                /* failed to reset keep-alive timer */
                goto ERR_CLOSE;
            }
        }
    }

    (void)pbuf_move_up(pbuf, TCP_GET_HDR_LEN(tcph));

    if (unlikely(TCP_EST_IS_ZERO_WIN(pcb))) {
        if (0 == tcph->win_size) {
            /* data not accepted till zero window cleared */
            err = ERR_SET_ERR(LUNE_ERR_TCP_UNEXPECTED_PKT);
            lune_log(LUNE_INFO, "received data with unexpected zero window at state %s"
                " on tcp connection %s",
                TCP_GET_STATE_STR(pcb->state),
                tcp_print_pcb_4tuple(pcb));
            goto ERR_RST_CLOSE;
        }

        TCP_CLEAR_EST_ZERO_WIN(pcb);
        if (TCP_IS_SERVER_SOCKET(pcb)) {
            if (likely(NULL != pcb->cb.accept)) {
                lune_socket_addr_t addr;
                addr.port = pcb->dst_port;
                addr.addr = pcb->dst_ip;
                SOCKET_PUSH_CB_SK(sk);
                pcb->cb.accept(SOCKET_X_GET_ID(sk), &addr, &pcb->cb.data);
                SOCKET_POP_CB_SK();
                if (unlikely(TCP_IS_SOCKET_CLOSED(sk))) {
                    /* socket has been reset or quiet closed in callback accept() */
                    return 0;
                }
            }
        } else {
            if (likely(NULL != pcb->cb.connect)) {
                SOCKET_PUSH_CB_SK(sk);
                pcb->cb.connect(pcb->cb.data);
                SOCKET_POP_CB_SK();
                if (unlikely(TCP_IS_SOCKET_CLOSED(sk))) {
                    /* socket has been reset or quiet closed in callback connect() */
                    return 0;
                }
            }
        }

        /*
            no need to start keep-alive timer right now, it will be
            done once data is processed below
        */
    }

    switch (pcb->state) {
    case TCP_FINWT1:
        if (pcb->last_ack == pcb->send_lbb) {
            tcp_update_state(pcb, TCP_FINWT2);
        }
        /* fall through */
    case TCP_FINWT2:
    case TCP_EST:
        if (unlikely(TCP_SEQ_GT(pcb->recv_nxt, tcph->seq_no))) {
            /* retransmitted packet, notify the other peer with updated ACK */
            if (0 != (err = tcp_send_ack(sk))) {
                lune_log(LUNE_INFO, "failed to send ACK at state %s on tcp connection %s: %s",
                    TCP_GET_STATE_STR(pcb->state),
                    tcp_print_pcb_4tuple(pcb),
                    ERR_GET_ERR_STR(err));
                goto ERR_CLOSE;
            }
            return 0;
        }

        if (unlikely(TCP_SEQ_LT(pcb->recv_nxt, tcph->seq_no))) {
            /* data doesn't arrive in order:( */
            pbuf_t *new_pbuf;
            pcb->send_wnd = tcph->win_size;
            if (NULL == (new_pbuf = pbuf_dup_pbuf(pbuf))) {
                err = ERR_GET_LAST_ERR();
                lune_log(LUNE_INFO, "failed to allocate new pbuf on tcp connection %s",
                    tcp_print_pcb_4tuple(pcb));
                goto ERR_RST_CLOSE;
            }

            /* cache it */
            tcp_insert_unordered_list(pcb, new_pbuf);
            if (0 != (err = tcp_send_ack(sk))) {
                lune_log(LUNE_INFO, "failed to send ACK at state %s on tcp connection %s: %s",
                    TCP_GET_STATE_STR(pcb->state),
                    tcp_print_pcb_4tuple(pcb),
                    ERR_GET_ERR_STR(err));
                goto ERR_CLOSE;
            }
        } else {
            return tcp_process_data(sk, pcb, pbuf);
        }

        break;
    case TCP_LASTACK:
        if (unlikely(TCP_SEQ_LEQ(pcb->recv_nxt, tcph->seq_no))) {
            /* suspicious, close it */
            err = ERR_SET_ERR(LUNE_ERR_TCP_UNEXPECTED_PKT);
            lune_log(LUNE_INFO, "received data with unexpected ack_no at state %s"
                " on tcp connection %s",
                TCP_GET_STATE_STR(pcb->state),
                tcp_print_pcb_4tuple(pcb));
            goto ERR_RST_CLOSE;
        }

        /* retransmitted packet, notify the other peer with updated ACK */
        if (0 != (err = tcp_send_ack(sk))) {
            lune_log(LUNE_INFO, "failed to send ACK at state %s on tcp connection %s: %s",
                TCP_GET_STATE_STR(pcb->state),
                tcp_print_pcb_4tuple(pcb),
                ERR_GET_ERR_STR(err));
            goto ERR_CLOSE;
        }

        break;
    default:
        err = ERR_SET_ERR(LUNE_ERR_TCP_UNEXPECTED_PKT);
        lune_log_once(LUNE_INFO, "received unexpected data with ACK at state %s on tcp connection %s",
            TCP_GET_STATE_STR(pcb->state),
            tcp_print_pcb_4tuple(pcb));
        goto ERR_RST_CLOSE;
    }

    return 0;

ERR_RST_CLOSE:
    if (0 != tcp_send_rst_ack(pcb)) {
        lune_log(LUNE_INFO, "failed to send RST at state %s on tcp connection %s: %s",
            TCP_GET_STATE_STR(pcb->state),
            tcp_print_pcb_4tuple(pcb),
            ERR_GET_LAST_ERR_STR());
    }

ERR_CLOSE:
    tcp_teardown_socket(sk, err);

    return err;
}

static inline int tcp_process_fin(socket_x_t *sk, lune_tcp_hdr_t *tcph)
{
    tcp_pcb_t *pcb = &sk->pcb.tcp;
    int err;

    switch (pcb->state) {
    case TCP_EST:
        if (unlikely(TCP_SEQ_NEQ(pcb->recv_nxt, tcph->seq_no))) {
            if (TCP_SEQ_GT(pcb->recv_nxt, tcph->seq_no)) {
                /* suspicious, close it */
                err = ERR_SET_ERR(LUNE_ERR_TCP_UNEXPECTED_PKT);
                lune_log(LUNE_INFO, "received FIN with unexpected seq_no at state %s"
                    " on tcp connection %s",
                    TCP_GET_STATE_STR(pcb->state),
                    tcp_print_pcb_4tuple(pcb));
                goto ERR_RST_CLOSE;
            }

            /*
                it looks like some packet(s) has lost, simply ignore it since
                it will be retransmitted anyway
            */
            return 0;
        }

        if (unlikely(TCP_EST_IS_ZERO_WIN(pcb))) {
            /* suspicious, close it */
            err = ERR_SET_ERR(LUNE_ERR_TCP_UNEXPECTED_PKT);
            lune_log(LUNE_INFO, "received FIN with zero window establishment at state %s"
                " on tcp connection %s",
                TCP_GET_STATE_STR(pcb->state),
                tcp_print_pcb_4tuple(pcb));
            goto ERR_RST_CLOSE;
        }

        TCP_ACK_SENT_CLEAR_FLAG(pcb);
        pcb->recv_nxt += 1;

        if (LUNE_TIMER_IS_ADDED(pcb->delay_rst_tmr)) {
            timer_del_timer(&pcb->delay_rst_tmr);
            socket_put(sk);
            return tcp_socket_rst_close_now(sk);
        }

        pcb->close_start_jiffies = TIMER_GET_CURRENT_JIFFIES();
        if (likely(NULL != pcb->ifp)) {
            lune_assert(0 != pcb->est_start_jiffies);
            net_if_tcp_add_session_duration(pcb->ifp, TIMER_GET_CURRENT_JIFFIES() - pcb->est_start_jiffies);
        }
        tcp_update_state(pcb, TCP_CLWAIT);

        if (NULL != pcb->cb.closewait) {
            SOCKET_PUSH_CB_SK(sk);
            pcb->cb.closewait(pcb->cb.data);
            SOCKET_POP_CB_SK();
            if (TCP_IS_SOCKET_CLOSED(sk)) {
                /* socket has been reset or quiet closed in callback closewait() */
                return 0;
            }
        }

        if (!TCP_ACK_IS_SENT(pcb)) {
            if (0 != (err = tcp_send_ack(sk))) {
                lune_log(LUNE_INFO, "failed to send ACK at state %s on tcp connection %s: %s",
                    TCP_GET_STATE_STR(pcb->state),
                    tcp_print_pcb_4tuple(pcb),
                    ERR_GET_ERR_STR(err));
                goto ERR_CLOSE;
            }
        }

        break;
    case TCP_CLWAIT:
        if (unlikely(TCP_SEQ_VAL(pcb->recv_nxt, tcph->seq_no) != 1)) {
            /* suspicious, close it */
            err = ERR_SET_ERR(LUNE_ERR_TCP_UNEXPECTED_PKT);
            lune_log(LUNE_INFO, "received FIN with unexpected seq_no at state %s"
                " on tcp connection %s",
                TCP_GET_STATE_STR(pcb->state),
                tcp_print_pcb_4tuple(pcb));
            goto ERR_RST_CLOSE;
        }

        if (0 != (err = tcp_send_ack(sk))) {
            lune_log(LUNE_INFO, "failed to send ACK at state %s on tcp connection %s: %s",
                TCP_GET_STATE_STR(pcb->state),
                tcp_print_pcb_4tuple(pcb),
                ERR_GET_ERR_STR(err));
            goto ERR_CLOSE;
        }

        break;
    case TCP_LASTACK:
    case TCP_CLOSING:
        if (unlikely(TCP_SEQ_VAL(pcb->recv_nxt, tcph->seq_no) != 1)) {
            /* suspicious, close it */
            err = ERR_SET_ERR(LUNE_ERR_TCP_UNEXPECTED_PKT);
            lune_log(LUNE_INFO, "received FIN with unexpected seq_no at state %s"
                " on tcp connection %s",
                TCP_GET_STATE_STR(pcb->state),
                tcp_print_pcb_4tuple(pcb));
            goto ERR_RST_CLOSE;
        }

        /*
            simply skip the retransmitted packet so that it will be acknowledged
            by retransmission of FIN+ACK
        */
        break;
    case TCP_FINWT1:
        if (unlikely(TCP_SEQ_NEQ(pcb->recv_nxt, tcph->seq_no))) {
            if (TCP_SEQ_GT(pcb->recv_nxt, tcph->seq_no)) {
                /* suspicious, close it */
                err = ERR_SET_ERR(LUNE_ERR_TCP_UNEXPECTED_PKT);
                lune_log(LUNE_INFO, "received FIN with unexpected seq_no at state %s"
                    " on tcp connection %s",
                    TCP_GET_STATE_STR(pcb->state),
                    tcp_print_pcb_4tuple(pcb));
                goto ERR_RST_CLOSE;
            }

            /*
                it looks like some packet(s) has lost, simply ignore it since
                it will be retransmitted anyway
            */
            break;
        }

        /* simultaneous closing */
        pcb->recv_nxt += 1;
        tcp_update_state(pcb, TCP_CLOSING);

        if (LUNE_TIMER_IS_ADDED(pcb->delack_tmr)) {
            timer_del_timer(&pcb->delack_tmr);
            socket_put(sk);     /* paired with delack hold */
        }

        if (0 != (err = tcp_send_ack_now(sk))) {
            lune_log(LUNE_INFO, "failed to send ACK at state %s on tcp connection %s: %s",
                TCP_GET_STATE_STR(pcb->state),
                tcp_print_pcb_4tuple(pcb),
                ERR_GET_ERR_STR(err));
            goto ERR_CLOSE;
        }

        break;
    case TCP_FINWT2:
        if (unlikely(TCP_SEQ_NEQ(pcb->recv_nxt, tcph->seq_no))) {
            if (TCP_SEQ_GT(pcb->recv_nxt, tcph->seq_no)) {
                /* suspicious, close it */
                err = ERR_SET_ERR(LUNE_ERR_TCP_UNEXPECTED_PKT);
                lune_log(LUNE_INFO, "received FIN with unexpected seq_no at state %s"
                    " on tcp connection %s",
                    TCP_GET_STATE_STR(pcb->state),
                    tcp_print_pcb_4tuple(pcb));
                goto ERR_RST_CLOSE;
            }

            /*
                it looks like some packet(s) has lost, simply ignore it since
                it will be retransmitted anyway
            */
            break;
        }

        pcb->recv_nxt += 1;

        tcp_send_ack_fast(sk);

        if (likely(NULL != pcb->ifp)) {
            NET_IF_TCP_INC_CLOSED_CONN(pcb->ifp);
            NET_IF_TCP_DEC_CONCURRENT_CONN(pcb->ifp);
            lune_assert(0 != pcb->close_start_jiffies);
            net_if_tcp_add_close_time(pcb->ifp, TIMER_GET_CURRENT_JIFFIES() - pcb->close_start_jiffies);
        }
        tcp_update_state(pcb, TCP_TWAIT);

        lune_assert(SOCKET_IS_CLOSED(sk));

        if (NULL != pcb->cb.close) {
            pcb->cb.close(pcb->cb.data, LUNE_TCP_SOCKET_CLOSE_NORMAL);
        }

        lune_assert(!LUNE_TIMER_IS_ADDED(pcb->time_wait_tmr));
        socket_hold(sk);
        timer_init_timer(&pcb->time_wait_tmr, LUNE_TIMER_ONCE,
            LUNE_TIMER_RES_HIGH, (lune_timer_func_t)tcp_time_wait_tmr_func, sk);
        timer_add_timer(&pcb->time_wait_tmr, TCP_DEFAULT_TWAIT_INTVL);

        break;
    case TCP_TWAIT:
        if (unlikely(TCP_SEQ_VAL(pcb->recv_nxt, tcph->seq_no) != 1)) {
            /* suspicious, close it */
            err = ERR_SET_ERR(LUNE_ERR_TCP_UNEXPECTED_PKT);
            lune_log(LUNE_INFO, "received FIN with unexpected seq_no at state %s"
                " on tcp connection %s",
                TCP_GET_STATE_STR(pcb->state),
                tcp_print_pcb_4tuple(pcb));
            goto ERR_RST_CLOSE;
        }

        /* send ACK right away */
        tcp_send_ack_fast(sk);

        /* renew time-wait timer */
        lune_assert(LUNE_TIMER_IS_ADDED(pcb->time_wait_tmr));
        timer_mod_timer(&pcb->time_wait_tmr, TCP_DEFAULT_TWAIT_INTVL);

        break;
    default:
        err = ERR_SET_ERR(LUNE_ERR_TCP_UNEXPECTED_PKT);
        lune_log_once(LUNE_INFO, "received unexpected FIN(+ACK) at state %s on tcp connection %s",
            TCP_GET_STATE_STR(pcb->state),
            tcp_print_pcb_4tuple(pcb));
        goto ERR_RST_CLOSE;
    }

    return 0;

ERR_RST_CLOSE:
    if (0 != tcp_send_rst_ack(pcb)) {
        lune_log(LUNE_INFO, "failed to send RST at state %s on tcp connection %s: %s",
            TCP_GET_STATE_STR(pcb->state),
            tcp_print_pcb_4tuple(pcb),
            ERR_GET_LAST_ERR_STR());
    }

ERR_CLOSE:
    tcp_teardown_socket(sk, err);

    return err;
}

static inline int tcp_process_syn(socket_x_t *sk,
    lune_ip_addr_t *dst_ip, lune_tcp_hdr_t *tcph)
{
    tcp_pcb_t *pcb = &sk->pcb.tcp;
    int err;
    pbuf_t *pbuf, *p;
    ip_t *ipp;
    tcp_state_en state;

    switch (pcb->state) {
    case TCP_TWAIT:
        lune_assert(LUNE_TIMER_IS_ADDED(pcb->time_wait_tmr));
        timer_del_timer(&pcb->time_wait_tmr);
        socket_put(sk);
        /* fall through */
    case TCP_LASTACK:
    case TCP_CLOSING:
        state = pcb->state;
        tcp_fini_state(pcb);
        if (likely(NULL != pcb->ifp)) {
            /* can we really take this as a normal closure? */
            NET_IF_TCP_INC_CLOSED_CONN(pcb->ifp);
            NET_IF_TCP_DEC_CONCURRENT_CONN(pcb->ifp);
            lune_assert(0 != pcb->close_start_jiffies);
            net_if_tcp_add_close_time(pcb->ifp, TIMER_GET_CURRENT_JIFFIES() - pcb->close_start_jiffies);
        }

        if (LUNE_TIMER_IS_ADDED(pcb->delack_tmr)) {
            timer_del_timer(&pcb->delack_tmr);
            socket_put(sk);     /* paired with delack hold */
        }

        lune_assert(!LUNE_TIMER_IS_ADDED(pcb->time_wait_tmr));

        if (LUNE_TIMER_IS_ADDED(pcb->retrans_tmr)) {
            timer_del_timer(&pcb->retrans_tmr);
            socket_put(sk);
        }

        tcp_free_all_pbuf(pcb);

        lune_assert(SOCKET_IS_CLOSED(sk));

        if (TCP_TWAIT != state
            && NULL != pcb->cb.close) {
            pcb->cb.close(pcb->cb.data, LUNE_TCP_SOCKET_CLOSE_NORMAL);
        }

        /* remove socket after callback close() so that it's not freed till now */
        lune_assert(!socket_remove(sk));

        /* must be called after socket_remove() */
        ipp = pcb->ipp;
        ip_put(pcb->ipp);
        pcb->ipp = NULL;
        if (likely(NULL != pcb->ifp)) {
            net_if_put(pcb->ifp);
            pcb->ifp = NULL;
        }

        return tcp_process_new_syn(ipp, dst_ip, tcph);
    case TCP_SYNR:
    {
        if (0 != (err = tcp_process_opt(pcb, tcph, (unsigned short)TCP_GET_OPT_HDR_LEN(tcph)))) {
            lune_log(LUNE_INFO, "failed to process tcp option at state %s"
                " on tcp connection %s: %s",
                TCP_GET_STATE_STR(pcb->state),
                tcp_print_pcb_4tuple(pcb),
                ERR_GET_ERR_STR(err));
            goto ERR_RST_CLOSE;
        }

#ifdef LUNE_DEBUG
        lune_assert(!dlist_is_empty(&pcb->unack_buf_list));
#endif

        pbuf = dlist_first(&pcb->unack_buf_list, pbuf_t, node);
        lune_assert(PBUF_GET_HDR(pbuf) == (void *)pbuf->tcp.hdr
            && PBUF_GET_PAYLOAD(pbuf) == (void *)pbuf->tcp.hdr);

        if (unlikely(2 < pbuf->tcp.retrans_times)) {
            lune_log_once(LUNE_INFO, "packet retransmission due to possible network"
                " overload and congestion at state %s on tcp connection %s",
                TCP_GET_STATE_STR(pcb->state),
                tcp_print_pcb_4tuple(pcb));
        }

        if (unlikely(!pbuf_is_last_ref(pbuf))) {
            /* pbuf still in use somewhere else */
            if (NULL == (p = pbuf_dup_pbuf(pbuf))) {
                lune_log(LUNE_INFO, "failed to duplicate pbuf at state %s"
                    " on tcp connection %s: %s",
                    TCP_GET_STATE_STR(pcb->state),
                    tcp_print_pcb_4tuple(pcb),
                    ERR_GET_LAST_ERR_STR());
                err = ERR_GET_LAST_ERR();
                goto ERR_RST_CLOSE;
            }

            dlist_replace(&p->node, &pbuf->node);
            pbuf_put(pbuf);
            pbuf = p;
            pbuf_hold(pbuf);
        }

        lune_assert(TCP_FLAG_SYN_ACK == pbuf->tcp.hdr->flags);
        /* refresh seq_no since it may not be consistent with previous one */
        pbuf->tcp.hdr->ack_no = lune_htonl(tcph->seq_no + 1);
        /* clear out retrans_times */
        pbuf->tcp.retrans_times = 0;
        lune_assert(0 == pbuf->tcp.data_len);
        PBUF_UPDATE_JIFFIES(pbuf);

        dlist_del(&pbuf->node);
        dlist_add_tail(&pbuf->node, &pcb->send_buf_list);

        lune_assert(LUNE_TIMER_IS_ADDED(pcb->retrans_tmr));
        timer_del_timer(&pcb->retrans_tmr);
        socket_put(sk);

        pcb->send_wnd = tcph->win_size;

        if (0 != (err = tcp_output_ctrl(sk))) {
            lune_log(LUNE_INFO, "failed to send SYN+ACK at state %s on tcp connection %s: %s",
                TCP_GET_STATE_STR(pcb->state),
                tcp_print_pcb_4tuple(pcb),
                ERR_GET_ERR_STR(err));
            goto ERR_CLOSE;
        }

        break;
    }
    default:
        err = ERR_SET_ERR(LUNE_ERR_TCP_UNEXPECTED_PKT);
        lune_log_once(LUNE_INFO, "received unexpected SYN at state %s on tcp connection %s",
            TCP_GET_STATE_STR(pcb->state),
            tcp_print_pcb_4tuple(pcb));
        goto ERR_RST_CLOSE;
    }

    return 0;

ERR_RST_CLOSE:
    if (0 != tcp_send_rst_ack(pcb)) {
        lune_log(LUNE_INFO, "failed to send RST at state %s on tcp connection %s: %s",
            TCP_GET_STATE_STR(pcb->state),
            tcp_print_pcb_4tuple(pcb),
            ERR_GET_LAST_ERR_STR());
    }

ERR_CLOSE:
    tcp_teardown_socket(sk, err);

    return err;
}

static inline int tcp_process_syn_ack(socket_x_t *sk, lune_tcp_hdr_t *tcph)
{
    tcp_pcb_t *pcb = &sk->pcb.tcp;
    int err;

    switch (pcb->state) {
    case TCP_EST:
        if (unlikely(TCP_SEQ_VAL(pcb->recv_nxt, tcph->seq_no) != 1
            /*
                send_lbb may be greater than ack_no in case
                some data has been sent
            */
            || TCP_SEQ_LT(pcb->send_lbb, tcph->ack_no)
            || pcb->last_ack != tcph->ack_no)) {
            err = ERR_SET_ERR(LUNE_ERR_TCP_UNEXPECTED_PKT);
            lune_log_once(LUNE_INFO, "received unexpected SYN+ACK at state %s on tcp connection %s",
                TCP_GET_STATE_STR(pcb->state),
                tcp_print_pcb_4tuple(pcb));
            goto ERR_RST_CLOSE;
        }

        if (unlikely(!TCP_EST_IS_ZERO_WIN(pcb)
            && 0 == tcph->win_size)) {
            err = ERR_SET_ERR(LUNE_ERR_TCP_UNEXPECTED_PKT);
            lune_log_once(LUNE_INFO, "received unexpected SYN+ACK at state %s on tcp connection %s",
                TCP_GET_STATE_STR(pcb->state),
                tcp_print_pcb_4tuple(pcb));
            goto ERR_RST_CLOSE;
        }

        tcp_send_ack_fast(sk);

        pcb->send_wnd = tcph->win_size;

        if (unlikely(TCP_EST_IS_ZERO_WIN(pcb)
            && 0 != tcph->win_size)) {
            TCP_CLEAR_EST_ZERO_WIN(pcb);
            if (likely(NULL != pcb->cb.connect)) {
                SOCKET_PUSH_CB_SK(sk);
                pcb->cb.connect(pcb->cb.data);
                SOCKET_POP_CB_SK();
                if (unlikely(TCP_IS_SOCKET_CLOSED(sk))) {
                    /* socket has been reset or quiet closed in callback connect() */
                    return 0;
                }
            }

            if (TCP_KEEP_ALIVE_ON(pcb)) {
                lune_assert(!LUNE_TIMER_IS_ADDED(pcb->keep_alive_tmr));
                /* start keep-alive timer */
                if (0 != (err = tcp_start_keep_alive(pcb, sk))) {
                    goto ERR_CLOSE;
                }

                return 0;
            }
        }

        break;
    case TCP_SYNS:
    {
        pbuf_t *pbuf;

        if (!TCP_SEQ_EQ(pcb->send_lbb, tcph->ack_no)) {
            /*
                it can be one of the following cases (or others):
                1. remote peer responded to an old duplicate SYN (refer to rfc793)
                2. mediate peer (such as anti-ddos device) responded to test if local
                   peer is bot
            */
            if (0 != (err = tcp_send_ctrl_pkt(pcb->ipp, &pcb->dst_ip, pcb->src_port,
                pcb->dst_port, tcph->ack_no, 0, TCP_FLAG_RST, 0))) {
                lune_log(LUNE_INFO, "failed to send ACK at state %s on tcp connection %s: %s",
                    TCP_GET_STATE_STR(pcb->state),
                    tcp_print_pcb_4tuple(pcb), ERR_GET_LAST_ERR_STR());
                goto ERR_CLOSE;
            }

            /* nothing has to be done, wait for the right SYN+ACK or to retransmit SYN */
            return 0;
        }

        if (0 != (err = tcp_process_opt(pcb, tcph, (unsigned short)TCP_GET_OPT_HDR_LEN(tcph)))) {
            lune_log(LUNE_INFO, "failed to process tcp option at state %s on tcp connection %s: %s",
                TCP_GET_STATE_STR(pcb->state),
                tcp_print_pcb_4tuple(pcb),
                ERR_GET_ERR_STR(err));
            goto ERR_RST_CLOSE;
        }

        lune_assert(dlist_one_node_only(&pcb->unack_buf_list));
        pbuf = dlist_first(&pcb->unack_buf_list, pbuf_t, node);
        dlist_del(&pbuf->node);
        pbuf_put(pbuf);

        lune_assert(LUNE_TIMER_IS_ADDED(pcb->retrans_tmr));
        timer_del_timer(&pcb->retrans_tmr);
        socket_put(sk);

        /* init recv_nxt */
        pcb->recv_nxt = tcph->seq_no + 1;
        pcb->send_wnd = tcph->win_size;
        pcb->last_ack = tcph->ack_no;

        if (TCP_EST_FASTACK_ON(pcb)) {
            if (0 != (err = tcp_send_ack_now(sk))) {
                lune_log(LUNE_INFO, "failed to send ACK at state %s on tcp connection %s: %s",
                    TCP_GET_STATE_STR(pcb->state),
                    tcp_print_pcb_4tuple(pcb),
                    ERR_GET_ERR_STR(err));
                goto ERR_CLOSE;
            }
        }

        /* bravo! tcp connection is established */
        pcb->est_start_jiffies = TIMER_GET_CURRENT_JIFFIES();
        if (likely(NULL != pcb->ifp)) {
            NET_IF_TCP_INC_ESTABLISHED_CONN(pcb->ifp);
            NET_IF_TCP_INC_CONCURRENT_CONN(pcb->ifp);
            lune_assert(0 != pcb->resp_start_jiffies);
            net_if_tcp_add_resp_time(pcb->ifp, TIMER_GET_CURRENT_JIFFIES() - pcb->resp_start_jiffies);
            lune_assert(0 != pcb->setup_start_jiffies);
            net_if_tcp_add_setup_time(pcb->ifp, TIMER_GET_CURRENT_JIFFIES() - pcb->setup_start_jiffies);
        }
        tcp_update_state(pcb, TCP_EST);

        if (unlikely(0 == tcph->win_size)) {
            /* hold off triggering connect event until further non-zero-window ACK received */
            TCP_SET_EST_ZERO_WIN(pcb);
            break;
        }

        if (likely(NULL != pcb->cb.connect)) {
            SOCKET_PUSH_CB_SK(sk);
            pcb->cb.connect(pcb->cb.data);
            SOCKET_POP_CB_SK();
            if (unlikely(TCP_IS_SOCKET_CLOSED(sk))) {
                /* socket has been reset or quiet closed in callback connect() */
                return 0;
            }

            if (unlikely(TCP_FINWT1 == pcb->state)) {
                /* socket has been normal closed in callback connect() */
                return 0;
            }

            if (!TCP_EST_FASTACK_ON(pcb)) {
                /*
                    No data sent in callback connect(), a single ACK is sent
                    to complete 3-way handshake
                */
                tcp_send_ack_fast(sk);
                TCP_EST_FASTACK_TURN_ON(pcb);
            }

            if (TCP_KEEP_ALIVE_ON(pcb)) {
                if (!LUNE_TIMER_IS_ADDED(pcb->keep_alive_tmr)) {
                    /* start keep-alive timer */
                    if (0 != (err = tcp_start_keep_alive(pcb, sk))) {
                        goto ERR_CLOSE;
                    }
                } else {
                    /* keep-alive timer already set in callback connect() */
                }

                return 0;
            }
        }

        break;
    }
    default:
        err = ERR_SET_ERR(LUNE_ERR_TCP_UNEXPECTED_PKT);
        lune_log_once(LUNE_INFO, "received unexpected SYN+ACK at state %s on tcp connection %s",
            TCP_GET_STATE_STR(pcb->state),
            tcp_print_pcb_4tuple(pcb));
        goto ERR_RST_CLOSE;
    }

    return 0;

ERR_RST_CLOSE:
    if (0 != tcp_send_rst_ack(pcb)) {
        lune_log(LUNE_INFO, "failed to send RST at state %s on tcp connection %s: %s",
            TCP_GET_STATE_STR(pcb->state),
            tcp_print_pcb_4tuple(pcb),
            ERR_GET_LAST_ERR_STR());
    }

ERR_CLOSE:
    tcp_teardown_socket(sk, err);

    return err;
}

int tcp_input(ip_t *ipp, const void *iph, pbuf_t *pbuf)
{
    socket_x_t *sk, psd_sk;
    tcp_pcb_t *pcb;
    unsigned int payload_len, is_ipv6;
    lune_tcp_hdr_t *n_tcph = (lune_tcp_hdr_t *)PBUF_GET_PAYLOAD(pbuf);
    lune_tcp_max_hdr_t h_tcph;
    lune_ip_addr_t dst_ip;
    unsigned char flags;
    int err;

    /* skip checksum check */
    h_tcph.hdr.src_port = lune_ntohs(n_tcph->src_port);
    h_tcph.hdr.dst_port = lune_ntohs(n_tcph->dst_port);
    h_tcph.hdr.win_size = lune_ntohs(n_tcph->win_size);
    h_tcph.hdr.seq_no = lune_ntohl(n_tcph->seq_no);
    h_tcph.hdr.ack_no = lune_ntohl(n_tcph->ack_no);
    h_tcph.hdr.hdr_len = n_tcph->hdr_len;
    h_tcph.hdr.flags = n_tcph->flags;
    h_tcph.hdr.csum = n_tcph->csum;
    h_tcph.hdr.urg_ptr = n_tcph->urg_ptr;
    if (TCP_GET_OPT_HDR_LEN(&h_tcph.hdr) > 0) {
        memcpy(h_tcph.opt, n_tcph + 1, TCP_GET_OPT_HDR_LEN(&h_tcph.hdr));
    }

    is_ipv6 = dst_ip.is_ipv6 = psd_sk.pcb.tcp.dst_ip.is_ipv6 = !!IP_IS_IPV6(ipp);
    if (is_ipv6) {
        /* ipv6 header passed from ip layer is network-byte-order */
        payload_len = lune_ntohs(((const lune_ipv6_hdr_t *)iph)->payload_len) - TCP_GET_HDR_LEN(&h_tcph.hdr);
        LUNE_IPV6_CPY(&psd_sk.pcb.tcp.dst_ip.ipv6, &((const lune_ipv6_hdr_t *)iph)->src_addr);
        LUNE_IPV6_CPY(&dst_ip.ipv6, &((const lune_ipv6_hdr_t *)iph)->src_addr);
    } else {
        /* ipv4 header passed from ip layer is host-byte-order */
        payload_len = ((const lune_ipv4_hdr_t *)iph)->total_len - IPV4_GET_HDR_LEN(iph) - TCP_GET_HDR_LEN(&h_tcph.hdr);
        dst_ip.ipv4 = psd_sk.pcb.tcp.dst_ip.ipv4 = ((const lune_ipv4_hdr_t *)iph)->src_addr;
    }

    PBUF_SET_L4_TYPE_TCP(pbuf);
    pbuf->tcp.data_len = payload_len;

    psd_sk.type = LUNE_SOCKET_TCP;
    psd_sk.ops = &g_socket_ops_tcp;
    psd_sk.pcb.tcp.ipp = ipp;
    psd_sk.pcb.tcp.src_port = h_tcph.hdr.dst_port;
    psd_sk.pcb.tcp.dst_port = h_tcph.hdr.src_port;
    if (NULL == (sk = (socket_x_t *)socket_find(&psd_sk))) {
        /* socket doesn't exist */
        if (TCP_FLAG_SYN == h_tcph.hdr.flags) {
            /* process new SYN */
            return tcp_process_new_syn(ipp, &dst_ip, &h_tcph.hdr);
        }

        if (!(TCP_FLAG_RST & h_tcph.hdr.flags)) {
            return tcp_send_ctrl_pkt(ipp, &dst_ip, h_tcph.hdr.dst_port, h_tcph.hdr.src_port,
                TCP_GET_NEW_SEQ_NO(), h_tcph.hdr.seq_no, TCP_FLAG_RST, 0);
        } else {
            /* ignore RST */
            return 0;
        }
    }

    /* hold it till tcp_input() returns */
    socket_hold(sk);

    pcb = &sk->pcb.tcp;
    if (TCP_SYNS == pcb->state) {
        if (TCP_FLAG_SYN_ACK == h_tcph.hdr.flags) {
            err = tcp_process_syn_ack(sk, &h_tcph.hdr);
            socket_put(sk);
            return err;
        }

        if (TCP_FLAG_RST & h_tcph.hdr.flags) {
            err = ERR_SET_ERR(LUNE_ERR_TCP_UNEXPECTED_PKT);
            goto ERR_CLOSE;
        }

        err = ERR_SET_ERR(LUNE_ERR_TCP_UNEXPECTED_PKT);
        lune_log(LUNE_INFO, "got suspicious flags %x at state %s on tcp connection %s: %s",
            h_tcph.hdr.flags,
            TCP_GET_STATE_STR(pcb->state),
            tcp_print_pcb_4tuple(pcb),
            ERR_GET_ERR_STR(err));

        goto ERR_RST_CLOSE;
    }

    flags = h_tcph.hdr.flags | ((payload_len > 0) ? TCP_FLAG_DATA : 0);
    switch (flags) {
    case TCP_FLAG_FIN:
        err = tcp_process_fin(sk, &h_tcph.hdr);
        socket_put(sk);
        return err;
    case TCP_FLAG_FIN_ACK:
        if (0 != (err = tcp_process_ack(sk, &h_tcph.hdr))
            || TCP_IS_SOCKET_CLOSED(sk)) {
            socket_put(sk);
            return err;
        }
        err = tcp_process_fin(sk, &h_tcph.hdr);
        socket_put(sk);
        return err;
    case TCP_FLAG_DATA_FIN_ACK:
    case TCP_FLAG_DATA_FIN_PSH_ACK:
        if (0 != (err = tcp_process_data_ack(sk, pbuf, &h_tcph.hdr))
            || TCP_IS_SOCKET_CLOSED(sk)) {
            socket_put(sk);
            return err;
        }
        h_tcph.hdr.seq_no += payload_len;
        err = tcp_process_fin(sk, &h_tcph.hdr);
        socket_put(sk);
        return err;
    case TCP_FLAG_SYN:
        err = tcp_process_syn(sk, &dst_ip, &h_tcph.hdr);
        socket_put(sk);
        return err;
    case TCP_FLAG_SYN_ACK:
        err = tcp_process_syn_ack(sk, &h_tcph.hdr);
        socket_put(sk);
        return err;
    case TCP_FLAG_RST:
    case TCP_FLAG_RST_ACK:
        err = tcp_process_rst(sk);
        socket_put(sk);
        return err;
    case TCP_FLAG_DATA_PSH_ACK:
    case TCP_FLAG_DATA_ACK:
        err = tcp_process_data_ack(sk, pbuf, &h_tcph.hdr);
        socket_put(sk);
        return err;
    case TCP_FLAG_ACK:
        err = tcp_process_ack(sk, &h_tcph.hdr);
        socket_put(sk);
        return err;
    default:
        /* tear connection down while receiving unexpected flags or data */
        err = ERR_SET_ERR(LUNE_ERR_TCP_UNEXPECTED_PKT);
        lune_log(LUNE_INFO, "got suspicious flags %x at state %s on tcp connection %s: %s",
            flags,
            TCP_GET_STATE_STR(pcb->state),
            tcp_print_pcb_4tuple(pcb),
            ERR_GET_ERR_STR(err));
        break;
    }

ERR_RST_CLOSE:
    /* reset closure */
    if (0 != tcp_send_rst_ack(pcb)) {
        lune_log(LUNE_INFO, "failed to send RST at state %s on tcp connection %s: %s",
            TCP_GET_STATE_STR(pcb->state),
            tcp_print_pcb_4tuple(pcb),
            ERR_GET_LAST_ERR_STR());
    }

ERR_CLOSE:
    tcp_teardown_socket(sk, err);

    socket_put(sk);

    return err;
}

static int tcp_socket_create(socket_x_t *sk)
{
    tcp_pcb_t *pcb = &sk->pcb.tcp;

    dlist_init_node(&pcb->node);

    pcb->ipp = NULL;
    pcb->ifp = NULL;
    LUNE_IP_INIT(&pcb->dst_ip);
    pcb->src_port = 0;
    pcb->dst_port = 0;

    pcb->flags = TCP_DELACK_FLAG | TCP_EST_FASTACK_FLAG;

    /* retransmit timer */
    timer_init_timer(&pcb->retrans_tmr, LUNE_TIMER_ONCE,
        LUNE_TIMER_RES_HIGH, (lune_timer_func_t)tcp_retrans_tmr_func, sk);
    /* delay-ACK timer */
    timer_init_timer(&pcb->delack_tmr, LUNE_TIMER_ONCE,
        LUNE_TIMER_RES_HIGH, (lune_timer_func_t)tcp_delack_tmr_func, sk);
    /* time-wait timer & delay-RST timer will be initialized only when needed */
    LUNE_TIMER_MINI_INIT(pcb->time_wait_tmr);
    /* keep-alive timer will be initialized only when set */
    LUNE_TIMER_MINI_INIT(pcb->keep_alive_tmr);

    pcb->last_ack = 0;
    pcb->recv_nxt = 0;
    pcb->send_lbb = TCP_GET_NEW_SEQ_NO();
    pcb->send_wnd = pcb->recv_wnd = TCP_DEFAULT_WND_SIZE;

    pcb->delack_intvl = TCP_DEFAULT_DELACK_INTVL;

    pcb->state = TCP_CLOSED;

    pcb->jiffies = TIMER_GET_CURRENT_JIFFIES();
    pcb->close_start_jiffies = 0;
    pcb->est_start_jiffies = 0;
    pcb->resp_start_jiffies = 0;
    pcb->setup_start_jiffies = 0;

    dlist_init_head(&pcb->send_buf_list);
    dlist_init_head(&pcb->unack_buf_list);
    dlist_init_head(&pcb->unordered_buf_list);

    memset(&pcb->cb, 0x00, sizeof(lune_tcp_socket_callback_t));
    pcb->listen_sk = NULL;

    return 0;
}

static inline unsigned short tcp_socket_get_max_hdr_len(tcp_pcb_t *pcb)
{
    unsigned short sub_entry_hdr_len;

    sub_entry_hdr_len = pbuf_get_max_hdr_len(
        IP_IS_IPV6(pcb->ipp) ? LUNE_ID_IPV6 : LUNE_ID_IPV4, pcb->ipp);
    return TCP_MAX_HDR_LEN + sub_entry_hdr_len;
}

unsigned short tcp_get_max_mss(tcp_pcb_t *pcb)
{
    return ip_get_mtu(pcb->ipp) - (IP_IS_IPV6(pcb->ipp)
        ? LUNE_IPV6_HDR_LEN : LUNE_IPV4_HDR_LEN) - LUNE_TCP_HDR_LEN;
}

static int tcp_socket_bind(socket_x_t *sk, const void *arg, unsigned int arg_len)
{
    ip_t *ipp;
    tcp_pcb_t *pcb;

    if (arg_len != sizeof(lune_socket_addr_t)) {
        return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
    }

    pcb = &sk->pcb.tcp;
    if (unlikely(NULL != pcb->ipp)) {
        return ERR_SET_ERR(LUNE_ERR_ALREADY_BOUND);
    }

    if (NULL == (ipp = ip_get_ip_by_id(((const lune_socket_addr_t *)arg)->id))) {
        return ERR_SET_ERR(LUNE_ERR_ID_NOT_FOUND);
    }

    if (IP_IS_SOCKET(ipp)) {
        return ERR_SET_ERR(LUNE_ERR_ALREADY_BOUND);
    }

    pcb->ipp = ipp;
    ip_hold(ipp);
    /* ipv4 or ipv6 not matter, will return the interface for ip */
    pcb->ifp = net_if_get_net_if_by_entry(LUNE_ID_IPV4, ipp);
    if (likely(NULL != pcb->ifp)) {
        net_if_hold(pcb->ifp);
    }
    pcb->src_port = ((const lune_socket_addr_t *)arg)->port;
    pcb->mss = tcp_get_max_mss(pcb);
    pcb->cwnd = pcb->mss * TCP_INIT_CWND_SEG_NUM;
    pcb->ss_thresh = pcb->mss * TCP_INIT_SS_THRESH_SEG_NUM;

    IP_SET_L4_SOCKET(ipp);

    sk->rsvd_hdr_len = tcp_socket_get_max_hdr_len(pcb);

    return 0;
}

static int tcp_socket_connect(socket_x_t *sk, const void *arg, unsigned int arg_len)
{
    tcp_pcb_t *pcb;
    int err;

    if (arg_len != sizeof(lune_socket_addr_t)) {
        return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
    }

    pcb = &sk->pcb.tcp;
    if (unlikely(NULL == pcb->ipp)) {
        return ERR_SET_ERR(LUNE_ERR_NOT_BOUND);
    }

    if (unlikely(TCP_SYNS == pcb->state)) {
        return ERR_SET_ERR(LUNE_ERR_SOCKET_CONNECTING);
    }

    if (unlikely(socket_is_added(sk))) {
        return ERR_SET_ERR(LUNE_ERR_SOCKET_ALREADY_CONNECTED);
    }

    if (unlikely(!!IP_IS_IPV6(pcb->ipp)
        != !!((const lune_socket_addr_t *)arg)->addr.is_ipv6)) {
        return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
    }

    lune_assert(TCP_CLOSED == pcb->state);

    pcb->dst_ip = ((const lune_socket_addr_t *)arg)->addr;
    pcb->dst_port = ((const lune_socket_addr_t *)arg)->port;

RETRY_CONNECT:
    if (0 != (err = socket_insert(sk))) {
        socket_x_t *sk2;
        tcp_pcb_t *pcb2;

        lune_assert(NULL != (sk2 = (socket_x_t *)socket_find(sk)));
        pcb2 = &sk2->pcb.tcp;
        if (TCP_TWAIT == pcb2->state) {
            /* reuse the connection at TCP_TWAIT by forcing the one to timeout */
            lune_assert(LUNE_TIMER_IS_ADDED(pcb2->time_wait_tmr));
            timer_del_timer(&pcb2->time_wait_tmr);
            tcp_time_wait_tmr_func(sk2);
            /*
                no socket_put is called here, reference count has been updated
                within timeout function
            */
            goto RETRY_CONNECT;
        }

        lune_log(LUNE_WARN, "failed to insert socket on tcp connection %s: %s",
            tcp_print_pcb_4tuple(pcb),
            ERR_GET_ERR_STR(err));
        return err;
    }

    if (0 != (err = tcp_enqueue_ctrl(sk, TCP_FLAG_SYN))) {
        lune_log(LUNE_INFO, "failed to enqueue SYN on tcp connection %s: %s",
            tcp_print_pcb_4tuple(pcb),
            ERR_GET_ERR_STR(err));
        lune_assert(!socket_remove(sk));
        return err;
    }

    if (0 != (err = tcp_output_ctrl(sk))) {
        tcp_dequeue_last_in_send_buf(pcb);
        lune_assert(!socket_remove(sk));
        return err;
    }

    pcb->resp_start_jiffies = pcb->setup_start_jiffies = TIMER_GET_CURRENT_JIFFIES();
    if (likely(NULL != pcb->ifp)) {
        NET_IF_TCP_INC_ATTEMPTED_CONN(pcb->ifp);
    }
    tcp_init_state(pcb, TCP_SYNS);

    return 0;
}

int tcp_local_init(void)
{
    s_tcp_init_seq_no = (unsigned int)lune_rand(0, (unsigned int)-1);
    s_tcp_retrans_intvl[0] = 1 * LUNE_TIME_SECOND;      /* 1 seconds */
    s_tcp_retrans_intvl[1] = 4 * LUNE_TIME_SECOND;      /* 3 seconds */
    s_tcp_retrans_intvl[2] = 10 * LUNE_TIME_SECOND;     /* 6 seconds */
    s_tcp_retrans_intvl[3] = 22 * LUNE_TIME_SECOND;     /* 12 seconds */
    /* 3 more seconds to wait and see if last one gets received */
    s_tcp_retrans_intvl[4] = 25 * LUNE_TIME_SECOND;
    s_tcp_listen_socket_cnt = 0;
    s_tcp_batch_listen_socket_cnt = 0;
    s_tcp_peer_listen_socket_cnt = 0;

    return 0;
}

void tcp_local_fini(void)
{
    s_tcp_listen_socket_cnt = 0;
    s_tcp_batch_listen_socket_cnt = 0;
    s_tcp_peer_listen_socket_cnt = 0;
    s_tcp_init_seq_no = 0;
}

static int tcp_socket_get_opt(socket_x_t *sk,
    lune_socket_opt_en opt, unsigned char *opt_val, unsigned int opt_len)
{
    tcp_pcb_t *pcb = &sk->pcb.tcp;

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
    case LUNE_SOCKET_OPT_GET_TCP_DELACK_INTVL:
        if (unlikely(NULL == opt_val || opt_len != sizeof(unsigned int))) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        *(unsigned int *)opt_val = pcb->delack_intvl / LUNE_TIME_MILLISECOND;
        break;
    case LUNE_SOCKET_OPT_GET_TCP_MSS:
        if (unlikely(NULL == opt_val || opt_len != sizeof(unsigned short))) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        if (NULL == pcb->ipp) {
            return ERR_SET_ERR(LUNE_ERR_NOT_BOUND);
        }

        *(unsigned short *)opt_val = pcb->mss;
        break;
    default:
        return ERR_SET_ERR(LUNE_ERR_OPT_NOT_FOUND);
    }

    return 0;
}

static int tcp_socket_set_opt(socket_x_t *sk,
    lune_socket_opt_en opt, const unsigned char *opt_val, unsigned int opt_len)
{
    tcp_pcb_t *pcb = &sk->pcb.tcp;
    int err;

    switch (opt) {
    case LUNE_SOCKET_OPT_SET_CALLBACK:
        if (unlikely(NULL == opt_val
            || opt_len != sizeof(lune_tcp_socket_callback_t))) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        if (NULL != ((const lune_tcp_socket_callback_t *)opt_val)->accept) {
            lune_log(LUNE_INFO, "attempted to register accept event"
                " on tcp socket %d", SOCKET_X_GET_ID(sk));
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        memcpy(&pcb->cb, opt_val, sizeof(lune_tcp_socket_callback_t));
        break;
    case LUNE_SOCKET_OPT_SET_CALLBACK_DATA:
        if (NULL == opt_val || opt_len != sizeof(void *)) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        pcb->cb.data = *(void * const *)opt_val;
        break;
    case LUNE_SOCKET_OPT_CLEAR_CALLBACK:
        if (unlikely(NULL != opt_val || 0 != opt_len)) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        memset(&pcb->cb, 0x00, sizeof(lune_tcp_socket_callback_t));
        break;
    case LUNE_SOCKET_OPT_SET_NORMAL_CLOSE:
        if (unlikely(NULL != opt_val || 0 != opt_len)) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        if (likely(TCP_GET_CLOSE_TYPE(pcb) != TCP_CLOSE_TYPE_NORMAL)) {
            TCP_SET_NORMAL_CLOSE(pcb);
        } else {
            lune_log(LUNE_INFO, "normal closure already set on tcp socket %d",
                SOCKET_X_GET_ID(sk));
        }

        break;
    case LUNE_SOCKET_OPT_SET_RST_CLOSE:
        if (unlikely(NULL != opt_val || 0 != opt_len)) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        if (likely(TCP_GET_CLOSE_TYPE(pcb) != TCP_CLOSE_TYPE_RST)) {
            TCP_SET_RST_CLOSE(pcb);
        }

        break;
    case LUNE_SOCKET_OPT_SET_QUIET_CLOSE:
        if (unlikely(NULL != opt_val || 0 != opt_len)) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        if (likely(TCP_GET_CLOSE_TYPE(pcb) != TCP_CLOSE_TYPE_QUIET)) {
            TCP_SET_QUIET_CLOSE(pcb);
        } else {
            lune_log(LUNE_INFO, "quiet closure already set on tcp socket %d",
                SOCKET_X_GET_ID(sk));
        }

        break;
    case LUNE_SOCKET_OPT_SET_TCP_MSS:
    {
        unsigned short max_mss;

        if (NULL == opt_val
            || opt_len != sizeof(unsigned short)) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        if (TCP_CLOSED != pcb->state) {
            /* mss can only be set before connect */
            return ERR_SET_ERR(LUNE_ERR_ALREADY_STARTED);
        }

        if (NULL == pcb->ipp) {
            /* mss can only be set after bind */
            return ERR_SET_ERR(LUNE_ERR_NOT_BOUND);
        }

        max_mss = tcp_get_max_mss(pcb);
        if (*(const unsigned short *)opt_val > max_mss) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        pcb->mss = *(const unsigned short *)opt_val;
        pcb->cwnd = pcb->mss * TCP_INIT_CWND_SEG_NUM;
        pcb->ss_thresh = pcb->mss * TCP_INIT_SS_THRESH_SEG_NUM;
        break;
    }
    case LUNE_SOCKET_OPT_SET_ALL_OR_NONE_XMIT:
        if (unlikely(NULL != opt_val || 0 != opt_len)) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        if (unlikely(TCP_ALL_OR_NONE_XMIT_ON(pcb))) {
            return ERR_SET_ERR(LUNE_ERR_ALREADY_SET);
        }

        TCP_ALL_OR_NONE_XMIT_TURN_ON(pcb);
        break;
    case LUNE_SOCKET_OPT_SET_TCP_ZERO_WIN:
        if (unlikely(NULL != opt_val || 0 != opt_len)) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        /* zero window can only be set before establishment */
        if (TCP_CLOSED != pcb->state
            && TCP_SYNS != pcb->state) {
            return ERR_SET_ERR(LUNE_ERR_NOT_SUPPORTED);
        }

        if (unlikely(TCP_ZERO_WIN_ON(pcb))) {
            return ERR_SET_ERR(LUNE_ERR_ALREADY_SET);
        }

        TCP_ZERO_WIN_TURN_ON(pcb);
        pcb->recv_wnd = 0;
        break;
    case LUNE_SOCKET_OPT_CLEAR_TCP_ZERO_WIN:
        if (unlikely(NULL != opt_val || 0 != opt_len)) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        if (unlikely(!TCP_ZERO_WIN_ON(pcb))) {
            return ERR_SET_ERR(LUNE_ERR_NOT_SET);
        }

        TCP_ZERO_WIN_TURN_OFF(pcb);
        pcb->recv_wnd = TCP_DEFAULT_WND_SIZE;

        if (TCP_CLOSED != pcb->state
            && TCP_SYNS != pcb->state) {
            if (0 != (err = tcp_send_ack_now(sk))) {
                /* rollback and report error */
                pcb->recv_wnd = 0;
                TCP_ZERO_WIN_TURN_ON(pcb);
                return err;
            }
        }

        break;
    case LUNE_SOCKET_OPT_SET_TCP_KEEP_ALIVE:
    {
        const lune_tcp_socket_keep_alive_param_t *keep_alive;

        if (unlikely(NULL == opt_val
            || opt_len != sizeof(lune_tcp_socket_keep_alive_param_t))) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        if (TCP_CLOSED != pcb->state
            && TCP_SYNS != pcb->state
            && TCP_EST != pcb->state) {
            return ERR_SET_ERR(LUNE_ERR_NOT_SUPPORTED);
        }

        keep_alive = (const lune_tcp_socket_keep_alive_param_t *)opt_val;
        if (keep_alive->time > LUNE_TCP_SOCKET_KEEP_ALIVE_MAX_TIME
            || keep_alive->intvl < LUNE_TCP_SOCKET_KEEP_ALIVE_MIN_INTVL
            || keep_alive->intvl > LUNE_TCP_SOCKET_KEEP_ALIVE_MAX_INTVL
            || keep_alive->probes < LUNE_TCP_SOCKET_KEEP_ALIVE_MIN_PROBES) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        pcb->keep_alive.time = keep_alive->time;
        pcb->keep_alive.intvl = keep_alive->intvl;
        pcb->keep_alive.probes = pcb->keep_alive_probes = keep_alive->probes;

        if (!TCP_KEEP_ALIVE_ON(pcb)) {
            lune_assert(!LUNE_TIMER_IS_ADDED(pcb->keep_alive_tmr));
            if (TCP_EST == pcb->state) {
                /* start keep-alive timer */
                if (0 != (err = tcp_start_keep_alive(pcb, sk))) {
                    return err;
                }
            } else {
                /* wait until connection established */
            }

            TCP_KEEP_ALIVE_TURN_ON(pcb);
            break;
        }

        if (TCP_EST == pcb->state) {
            lune_assert(LUNE_TIMER_IS_ADDED(pcb->keep_alive_tmr));
            if (0 != (err = tcp_restart_keep_alive(pcb))) {
                /* keep-alive timer will be stopped if it fails to reload new conf */
                tcp_stop_keep_alive(pcb, sk);
                TCP_KEEP_ALIVE_TURN_OFF(pcb);
                return err;
            }
        }

        break;
    }
    case LUNE_SOCKET_OPT_CLEAR_TCP_KEEP_ALIVE:
        if (!TCP_KEEP_ALIVE_ON(pcb)) {
            return ERR_SET_ERR(LUNE_ERR_NOT_SET);
        }

        if (LUNE_TIMER_IS_ADDED(pcb->keep_alive_tmr)) {
            lune_assert(TCP_EST == pcb->state);
            tcp_stop_keep_alive(pcb, sk);
        }

        TCP_KEEP_ALIVE_TURN_OFF(pcb);
        break;
    case LUNE_SOCKET_OPT_SET_TCP_DELACK:
        if (unlikely(NULL != opt_val || 0 != opt_len)) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        if (TCP_DELACK_ON(pcb)) {
            return ERR_SET_ERR(LUNE_ERR_ALREADY_SET);
        }

        TCP_DELACK_TURN_ON(pcb);
        break;
    case LUNE_SOCKET_OPT_CLEAR_TCP_DELACK:
        if (unlikely(NULL != opt_val || 0 != opt_len)) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        if (!TCP_DELACK_ON(pcb)) {
            return ERR_SET_ERR(LUNE_ERR_NOT_SET);
        }

        TCP_DELACK_TURN_OFF(pcb);

        if (LUNE_TIMER_IS_ADDED(pcb->delack_tmr)) {
            tcp_send_ack_fast(sk);
        }

        break;
    case LUNE_SOCKET_OPT_CLEAR_TCP_EST_FASTACK:
        if (unlikely(NULL != opt_val || 0 != opt_len)) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        if (!TCP_EST_FASTACK_ON(pcb)) {
            return ERR_SET_ERR(LUNE_ERR_NOT_SET);
        }

        /* 3-handshake fast ACK only works for establishment */
        if (TCP_CLOSED != pcb->state
            && TCP_SYNS != pcb->state) {
            return ERR_SET_ERR(LUNE_ERR_NOT_SUPPORTED);
        }

        TCP_EST_FASTACK_TURN_OFF(pcb);
        break;
    case LUNE_SOCKET_OPT_SET_TCP_DELACK_INTVL:
    {
        unsigned int intvl;

        if (NULL == opt_val
            || opt_len != sizeof(unsigned int)) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        intvl = *(const unsigned int *)opt_val;
        if (0 == intvl || intvl > LUNE_TCP_MAX_DELACK_INTVL) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        pcb->delack_intvl = intvl * LUNE_TIME_MILLISECOND;
        break;
    }
    default:
        return ERR_SET_ERR(LUNE_ERR_OPT_NOT_FOUND);
    }

    return 0;
}

static int tcp_socket_close(socket_x_t *sk)
{
    tcp_pcb_t *pcb = &sk->pcb.tcp;
    int err;

    lune_assert(!LUNE_TIMER_IS_ADDED(pcb->time_wait_tmr));

    if (unlikely(TCP_CLOSED == pcb->state)) {
        /* client socket not bound or connected yet */
        lune_assert(!LUNE_TIMER_IS_ADDED(pcb->retrans_tmr));
        lune_assert(!socket_is_added(sk));

        if (NULL != pcb->ipp) {
            /* bound but tcp yet connected */
            ip_put(pcb->ipp);
            pcb->ipp = NULL;
            if (likely(NULL != pcb->ifp)) {
                net_if_put(pcb->ifp);
                pcb->ifp = NULL;
            }
        }

        return 0;
    }

    if (TCP_CLOSE_TYPE_RST == TCP_GET_CLOSE_TYPE(pcb)) {
        if (unlikely(TCP_SEQ_NEQ(pcb->send_lbb, pcb->last_ack))) {
            if (TCP_SYNS == pcb->state) {
                /* connection attempted but yet established */
                goto RST_CLOSE;
            }

            /*
                delay RST closure to prevent sending RST following data
                having just been sent

                in this case, the other peer may send ACK before receiving
                RST and cause a redundant RST to be sent from the local
                since the local connection has been closed

                just notice that delay_rst_tmr reuses the field of
                time_wait_tmr as they don't happen at the same time
            */
            lune_assert(!LUNE_TIMER_IS_ADDED(pcb->delay_rst_tmr));
            socket_hold(sk);
            timer_init_timer(&pcb->delay_rst_tmr, LUNE_TIMER_ONCE,
                LUNE_TIMER_RES_HIGH, (lune_timer_func_t)tcp_delay_rst_tmr_func, sk);
            timer_add_timer(&pcb->delay_rst_tmr, TCP_DEFAULT_DELAY_RST_INTVL);

            /* closure finished and socket inaccessible */
            return 0;
        }

        goto RST_CLOSE;
    } else if (TCP_CLOSE_TYPE_QUIET == TCP_GET_CLOSE_TYPE(pcb)) {
        goto CLOSE;
    }

    switch (pcb->state) {
    case TCP_SYNS:
        /* still connecting */
        goto RST_CLOSE;
    case TCP_EST:
        /* established, active close */
        if (0 != (err = tcp_enqueue_ctrl(sk, TCP_FLAG_FIN_ACK))) {
            lune_log(LUNE_INFO, "failed to enqueue FIN+ACK at state %s"
                " on tcp connection %s: %s",
                TCP_GET_STATE_STR(pcb->state),
                tcp_print_pcb_4tuple(pcb),
                ERR_GET_ERR_STR(err));
            goto ERR_RST_CLOSE;
        }

        if (0 != (err = tcp_output_ctrl(sk))) {
            lune_log(LUNE_INFO, "failed to send FIN+ACK at state %s"
                " on tcp connection %s: %s",
                TCP_GET_STATE_STR(pcb->state),
                tcp_print_pcb_4tuple(pcb),
                ERR_GET_ERR_STR(err));
            if (-LUNE_ERR_NET_IF_SEND_FAILED == err) {
                tcp_dequeue_last_in_send_buf(pcb);
                return err;
            }
            goto ERR_CLOSE;
        }

        pcb->close_start_jiffies = TIMER_GET_CURRENT_JIFFIES();
        if (likely(NULL != pcb->ifp)) {
            lune_assert(0 != pcb->est_start_jiffies);
            net_if_tcp_add_session_duration(pcb->ifp, TIMER_GET_CURRENT_JIFFIES() - pcb->est_start_jiffies);
        }
        tcp_update_state(pcb, TCP_FINWT1);
        break;
    case TCP_CLWAIT:
        /* passive close */
        if (0 != (err = tcp_enqueue_ctrl(sk, TCP_FLAG_FIN_ACK))) {
            lune_log(LUNE_INFO, "failed to enqueue FIN+ACK at state %s"
                " on tcp connection %s: %s",
                TCP_GET_STATE_STR(pcb->state),
                tcp_print_pcb_4tuple(pcb),
                ERR_GET_ERR_STR(err));
            goto ERR_RST_CLOSE;
        }

        if (0 != (err = tcp_output_ctrl(sk))) {
            lune_log(LUNE_INFO, "failed to send FIN+ACK at state %s"
                " on tcp connection %s: %s",
                TCP_GET_STATE_STR(pcb->state),
                tcp_print_pcb_4tuple(pcb),
                ERR_GET_ERR_STR(err));
            if (-LUNE_ERR_NET_IF_SEND_FAILED == err) {
                tcp_dequeue_last_in_send_buf(pcb);
                return err;
            }
            goto ERR_CLOSE;
        }

        tcp_update_state(pcb, TCP_LASTACK);
        break;
    case TCP_SYNR:
        /* fall through ... just curious how you get the socket id?? */
    default:
        lune_log(LUNE_WARN, "unexpected state %s while closing tcp connection %s",
            TCP_GET_STATE_STR(pcb->state),
            tcp_print_pcb_4tuple(pcb));
        err = ERR_SET_ERR(LUNE_ERR_TCP_INTERNAL);
        goto ERR_RST_CLOSE;
    }

    TCP_ACK_SENT_SET_FLAG(pcb);

    return 0;

ERR_RST_CLOSE:
    if (0 != tcp_send_rst_ack(pcb)) {
        lune_log(LUNE_INFO, "failed to send RST at state %s on tcp connection %s: %s",
            TCP_GET_STATE_STR(pcb->state),
            tcp_print_pcb_4tuple(pcb),
            ERR_GET_ERR_STR(err));
    }

ERR_CLOSE:
    lune_assert(SOCKET_IS_CLOSED(sk));
    /* socket_close() won't be called within tcp_teardown_socket() */
    lune_assert(!socket_close(sk));
    tcp_teardown_socket(sk, err);

    return err;

RST_CLOSE:
    if (0 != (err = tcp_send_rst_ack(pcb))) {
        lune_log(LUNE_INFO, "failed to send RST at state %s on tcp connection %s: %s",
            TCP_GET_STATE_STR(pcb->state),
            tcp_print_pcb_4tuple(pcb),
            ERR_GET_ERR_STR(err));
        if (-LUNE_ERR_NET_IF_SEND_FAILED == err) {
            return err;
        }
    }

CLOSE:
    if (LUNE_TIMER_IS_ADDED(pcb->retrans_tmr)) {
        timer_del_timer(&pcb->retrans_tmr);
        socket_put(sk);
    }

    if (LUNE_TIMER_IS_ADDED(pcb->delack_tmr)) {
        timer_del_timer(&pcb->delack_tmr);
        socket_put(sk);
    }

    if (likely(NULL != pcb->ifp)) {
        if (TCP_SYNS == pcb->state) {
            NET_IF_TCP_INC_ABORTED_CONN(pcb->ifp);
        } else {
            if (TCP_EST == pcb->state) {
                lune_assert(0 != pcb->est_start_jiffies);
                net_if_tcp_add_session_duration(pcb->ifp, TIMER_GET_CURRENT_JIFFIES() - pcb->est_start_jiffies);
            }
            NET_IF_TCP_INC_CLOSED_CONN(pcb->ifp);
            NET_IF_TCP_DEC_CONCURRENT_CONN(pcb->ifp);
        }
    }
    tcp_fini_state(pcb);

    tcp_free_all_pbuf(pcb);

    lune_assert(SOCKET_IS_CLOSED(sk));

    /* either reset close or quiet close */
    if (NULL != pcb->cb.close) {
        pcb->cb.close(pcb->cb.data,
            LUNE_TCP_SOCKET_CLOSE_QUIET == TCP_GET_CLOSE_TYPE(pcb)
            ? LUNE_TCP_SOCKET_CLOSE_QUIET
            : LUNE_TCP_SOCKET_CLOSE_RST);
    }

    lune_assert(!socket_remove(sk));

    /* must be called after socket_remove() */
    ip_put(pcb->ipp);
    pcb->ipp = NULL;
    if (likely(NULL != pcb->ifp)) {
        net_if_put(pcb->ifp);
        pcb->ifp = NULL;
    }

    return 0;
}

static int tcp_socket_send(socket_x_t *sk, const unsigned char *buf, unsigned int buf_len)
{
    int frag_len, send_len, sent_len, len;
    tcp_pcb_t *pcb = &sk->pcb.tcp;
    int eff_cwnd, sent;

#ifdef LUNE_DEBUG
    lune_assert(TCP_CLOSED == pcb->state || TCP_CLWAIT == pcb->state
        || TCP_SYNS == pcb->state || TCP_EST == pcb->state);
    lune_assert(dlist_is_empty(&pcb->send_buf_list));
#endif

    if (TCP_EST != pcb->state && TCP_CLWAIT != pcb->state) {
        lune_log(LUNE_INFO, "attempted to send data at state %s on tcp connection %s",
            TCP_GET_STATE_STR(pcb->state),
            tcp_print_pcb_4tuple(pcb));
        return ERR_SET_ERR(LUNE_ERR_SOCKET_NOT_CONNECTED);
    }

    eff_cwnd = (int)((pcb->cwnd > pcb->send_wnd) ? pcb->send_wnd : pcb->cwnd);
    sent = (int)TCP_SEQ_VAL(pcb->send_lbb, pcb->last_ack);
    if ((eff_cwnd - sent) < (int)buf_len) {
        /* congestion window smaller than data to be sent */
        if (0 >= (eff_cwnd - sent) || TCP_ALL_OR_NONE_XMIT_ON(pcb)) {
            /* either zero window or fail to send all */
            return 0;
        }

        buf_len = eff_cwnd - sent;
    }

    send_len = frag_len = 0;
    do {
        frag_len = buf_len > pcb->mss ? pcb->mss : buf_len;

        len = tcp_enqueue_data(sk, buf + send_len, frag_len, TCP_FLAG_PSH_ACK);
        if (unlikely(len < 0)) {
            if (send_len > 0) {
                tcp_dequeue_data_in_send_buf(pcb);
            }
            return len;
        }

        send_len += len;
        buf_len -= len;

        if (len < frag_len) {
            /* oops, congestion window full */
            break;
        }
    } while (buf_len > 0);

    lune_assert(buf_len >= 0);

    sent_len = 0;
    if (send_len > 0) {
        if (unlikely(send_len > (sent_len = tcp_output_data(sk)))) {
            lune_log(LUNE_DBG, "%d data sent, less than expected (%d)"
                " at state %s on tcp connection %s: %s",
                sent_len, send_len,
                TCP_GET_STATE_STR(pcb->state),
                tcp_print_pcb_4tuple(pcb),
                ERR_GET_LAST_ERR_STR());

            tcp_free_send_pbuf(pcb);
        }
    }

    return sent_len;
}

static int tcp_socket_send_pkts(socket_x_t *sk,
    lune_socket_send_pkt_t *pkts, unsigned int pkt_num, unsigned int mode)
{
    unsigned int i;
    int frag_len, send_len, sent_len, len, total_len, offset;
    int eff_cwnd, sent;
    tcp_pcb_t *pcb;

    if (LUNE_SOCKET_SEND_PKTS_UNCHANGED == mode) {
        sent_len = 0;
        for (i = 0; i < pkt_num; i++) {
            if ((int)pkts[i].len != (send_len = tcp_socket_send(sk, pkts[i].buf, pkts[i].len))) {
                if (send_len <= 0) {
                    if (0 == i) {
                        /* no packet sent, return either 0 or error code */
                        return send_len;
                    } else {
                        /* return sent length */
                    }
                } else {
                    /* less data sent than designated, return sent length */
                    sent_len += send_len;
                }
                break;
            }
            sent_len += pkts[i].len;
        }

        return sent_len;
    }

    pcb = &sk->pcb.tcp;
    lune_assert(TCP_CLOSED == pcb->state || TCP_CLWAIT == pcb->state
        || TCP_SYNS == pcb->state || TCP_EST == pcb->state);
    lune_assert(dlist_is_empty(&pcb->send_buf_list));

    if (TCP_EST != pcb->state && TCP_CLWAIT != pcb->state) {
        lune_log(LUNE_INFO, "attempted to send data at state %s"
            " on tcp connection %s",
            TCP_GET_STATE_STR(pcb->state),
            tcp_print_pcb_4tuple(pcb));
        return ERR_SET_ERR(LUNE_ERR_SOCKET_NOT_CONNECTED);
    }

    total_len = 0;
    for (i = 0; i < pkt_num; i++) {
        total_len += pkts[i].len;
    }

    eff_cwnd = (int)((pcb->cwnd > pcb->send_wnd) ? pcb->send_wnd : pcb->cwnd);
    sent = (int)TCP_SEQ_VAL(pcb->send_lbb, pcb->last_ack);
    if ((eff_cwnd - sent) < total_len) {
        /* congestion window smaller than data to be sent */
        if (0 >= (eff_cwnd - sent) || TCP_ALL_OR_NONE_XMIT_ON(pcb)) {
            /* either zero window or fail to send all */
            return 0;
        }

        total_len = eff_cwnd - sent;
    }

    send_len = frag_len = offset = 0;
    do {
        frag_len = total_len > pcb->mss ? pcb->mss : total_len;

        len = tcp_enqueue_data_x(sk, pkts, offset, frag_len, TCP_FLAG_PSH_ACK);
        if (unlikely(len < 0)) {
            if (send_len > 0) {
                tcp_dequeue_data_in_send_buf(pcb);
            }
            return len;
        }

        send_len += len;
        total_len -= len;

        if (len < frag_len) {
            /* oops, congestion window full */
            break;
        }

        do {
            if (len >= ((int)pkts->len - offset)) {
                len -= ((int)pkts->len - offset);
                pkts++;
                offset = 0;
            } else {
                offset += len;
                break;
            }
        } while (len > 0);
    } while (total_len > 0);

    lune_assert(total_len >= 0);

    sent_len = 0;
    if (send_len > 0) {
        if (unlikely(send_len > (sent_len = tcp_output_data(sk)))) {
            lune_log(LUNE_DBG, "%d data sent, less than expected (%d)"
                " at state %s on tcp connection %s: %s",
                sent_len, send_len,
                TCP_GET_STATE_STR(pcb->state),
                tcp_print_pcb_4tuple(pcb),
                ERR_GET_LAST_ERR_STR());

            tcp_free_send_pbuf(pcb);
        }
    }

    return sent_len;
}

static unsigned int tcp_socket_hash(socket_x_pcb_un *pcb)
{
    return pcb->tcp.dst_ip.is_ipv6
        ? ((((lune_ntohl(pcb->tcp.ipp->ipv6.ip.addr[3])
        + lune_ntohl(pcb->tcp.dst_ip.ipv6.addr[3])) << 11) +
        ((pcb->tcp.src_port + pcb->tcp.dst_port) & 0x7ff)) & SOCKET_HTABLE_MASK)
        : ((((pcb->tcp.ipp->ipv4.ip + pcb->tcp.dst_ip.ipv4) << 11) +
        ((pcb->tcp.src_port + pcb->tcp.dst_port) & 0x7ff)) & SOCKET_HTABLE_MASK);
}

static int tcp_socket_compare(socket_x_pcb_un *pcb1, socket_x_pcb_un *pcb2)
{
    return (pcb1->tcp.ipp == pcb2->tcp.ipp
        && pcb1->tcp.src_port == pcb2->tcp.src_port
        && pcb1->tcp.dst_port == pcb2->tcp.dst_port
        && (!LUNE_IP_CMP(&pcb1->tcp.dst_ip, &pcb2->tcp.dst_ip))) ? 0 : 1;
}

socket_ops_t g_socket_ops_tcp = {
    .create = (socket_create_func_t)tcp_socket_create,
    .bind = (socket_bind_func_t)tcp_socket_bind,
    .connect = (socket_connect_func_t)tcp_socket_connect,
    .listen = NULL,
    .send = (socket_send_func_t)tcp_socket_send,
    .send_pkts = (socket_send_pkts_func_t)tcp_socket_send_pkts,
    .sendto = NULL,
    .get_opt = (socket_get_opt_func_t)tcp_socket_get_opt,
    .set_opt = (socket_set_opt_func_t)tcp_socket_set_opt,
    .close = (socket_close_func_t)tcp_socket_close,
    .hash = (socket_hash_func_t)tcp_socket_hash,
    .compare = (socket_compare_func_t)tcp_socket_compare,
    .get_max_hdr_len = NULL,
};

static int tcp_listen_socket_create(socket_t *listen_sk)
{
    tcp_listen_pcb_t *listen_pcb = &listen_sk->pcb.tcp_listen;

    dlist_init_head(&listen_pcb->backlog_list);
    listen_pcb->ipp = NULL;
    listen_pcb->ifp = NULL;
    listen_pcb->state = TCP_CLOSED;
    listen_pcb->port = 0;
    listen_pcb->flags = TCP_DELACK_FLAG;
    listen_pcb->delack_intvl = TCP_DEFAULT_DELACK_INTVL;
    listen_pcb->jiffies = TIMER_GET_CURRENT_JIFFIES();
    listen_pcb->backlog = LUNE_TCP_LISTEN_DEFAULT_BACKLOG;
    listen_pcb->backlog_cnt = 0;
    memset(&listen_pcb->cb, 0x00, sizeof(lune_tcp_socket_callback_t));

    return 0;
}

static int tcp_listen_socket_close(socket_t *listen_sk)
{
    tcp_listen_pcb_t *listen_pcb = &listen_sk->pcb.tcp_listen;
    tcp_pcb_t *pcb, *pcb2;

    if (NULL == listen_pcb->ipp) {
        /* socket not bound yet */
        return 0;
    }

    dlist_for_each_node_safe(pcb, pcb2, &listen_pcb->backlog_list, node) {
        socket_x_t *sk = SOCKET_X_GET_SK_BY_PCB(pcb);

        lune_assert(TCP_SYNR == pcb->state);
        lune_assert(!SOCKET_IS_CLOSED(sk));
        lune_assert(!LUNE_TIMER_IS_ADDED(pcb->delack_tmr));

        if (0 != tcp_send_rst_ack(pcb)) {
            lune_log(LUNE_INFO, "failed to send RST at state %s"
                " on tcp connection %s: %s",
                TCP_GET_STATE_STR(pcb->state),
                tcp_print_pcb_4tuple(pcb),
                ERR_GET_LAST_ERR_STR());
        }

        tcp_fini_state(pcb);
        lune_assert(!socket_remove(sk));
        tcp_delete_passive_socket(sk);
    }

    lune_assert(0 == listen_pcb->backlog_cnt);

    if (socket_is_listen_socket_added(listen_sk)) {
        tcp_listen_fini_state(listen_pcb);
        lune_assert(!socket_listen_socket_remove(listen_sk));
    }

    if (LUNE_SOCKET_TCP_BATCH_LISTEN == listen_sk->type) {
        s_tcp_batch_listen_socket_cnt--;
    } else if (LUNE_SOCKET_TCP_PEER_LISTEN == listen_sk->type) {
        s_tcp_peer_listen_socket_cnt--;
    } else {
        lune_assert(LUNE_SOCKET_TCP_LISTEN == listen_sk->type);
        s_tcp_listen_socket_cnt--;
    }

    if (listen_pcb->ipp->tcp_listen_sk == listen_sk) {
        socket_put(listen_sk);
        listen_pcb->ipp->tcp_listen_sk = NULL;
    }

    /* must be called after socket_remove() */
    ip_put(listen_pcb->ipp);
    listen_pcb->ipp = NULL;
    if (likely(NULL != listen_pcb->ifp)) {
        net_if_put(listen_pcb->ifp);
        listen_pcb->ifp = NULL;
    }

    return 0;
}

static inline unsigned short tcp_listen_socket_get_max_hdr_len(tcp_listen_pcb_t *pcb)
{
    unsigned short sub_entry_hdr_len;

    lune_assert(NULL != pcb->ipp);

    sub_entry_hdr_len = pbuf_get_max_hdr_len(
        IP_IS_IPV6(pcb->ipp) ? LUNE_ID_IPV6 : LUNE_ID_IPV4, pcb->ipp);
    return TCP_MAX_HDR_LEN + sub_entry_hdr_len;
}

unsigned short tcp_listen_get_max_mss(tcp_listen_pcb_t *pcb)
{
    return ip_get_mtu(pcb->ipp) - (IP_IS_IPV6(pcb->ipp)
        ? LUNE_IPV6_HDR_LEN : LUNE_IPV4_HDR_LEN) - LUNE_TCP_HDR_LEN;
}

static int tcp_listen_socket_bind(socket_t *sk, const void *arg, unsigned int arg_len)
{
    ip_t *ipp;
    tcp_listen_pcb_t *pcb;

    if (arg_len != sizeof(lune_socket_addr_t)) {
        return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
    }

    pcb = &sk->pcb.tcp_listen;
    if (NULL != pcb->ipp) {
        return ERR_SET_ERR(LUNE_ERR_ALREADY_BOUND);
    }

    if (NULL == (ipp = ip_get_ip_by_id(((const lune_socket_addr_t *)arg)->id))) {
        return ERR_SET_ERR(LUNE_ERR_ID_NOT_FOUND);
    }

    if (IP_IS_SOCKET(ipp)) {
        return ERR_SET_ERR(LUNE_ERR_ALREADY_BOUND);
    }

    pcb->ipp = ipp;
    ip_hold(ipp);
    /* ipv4 or ipv6 not matter, will return the interface for ip */
    pcb->ifp = net_if_get_net_if_by_entry(LUNE_ID_IPV4, ipp);
    if (likely(NULL != pcb->ifp)) {
        net_if_hold(pcb->ifp);
    }
    pcb->port = ((const lune_socket_addr_t *)arg)->port;

    pcb->init_mss = tcp_listen_get_max_mss(pcb);
    pcb->init_cwnd = pcb->init_mss * TCP_INIT_CWND_SEG_NUM;
    pcb->init_ss_thresh = pcb->init_mss * TCP_INIT_SS_THRESH_SEG_NUM;

    IP_SET_L4_SOCKET(ipp);

    sk->rsvd_hdr_len = tcp_listen_socket_get_max_hdr_len(pcb);

    return 0;
}

static int tcp_listen_socket_listen(socket_t *sk, unsigned int backlog)
{
    tcp_listen_pcb_t *pcb = &sk->pcb.tcp_listen;
    socket_t psd_sk;
    int err;

    if (NULL == pcb->ipp) {
        return ERR_SET_ERR(LUNE_ERR_NOT_BOUND);
    }

    if (backlog > LUNE_TCP_LISTEN_MAX_BACKLOG) {
        return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
    }

    pcb->backlog = backlog;

    if (s_tcp_batch_listen_socket_cnt > 0) {
        psd_sk.type = LUNE_SOCKET_TCP_BATCH_LISTEN;
        psd_sk.ops = &g_socket_ops_tcp_batch_listen;
        psd_sk.pcb.tcp_listen.ipp = pcb->ipp;
        psd_sk.pcb.tcp_listen.port = pcb->port;
        psd_sk.pcb.tcp_listen.end_port = 0;
        if (NULL != socket_listen_socket_find(&psd_sk)) {
            return ERR_SET_ERR(LUNE_ERR_ALREADY_BOUND);
        }
    }

    if (s_tcp_peer_listen_socket_cnt > 0) {
        /*
            unable to detect if a peer listen socket has been
            established on the same <local ip, local port>.
            just log and move on
        */
        lune_log_once(LUNE_DBG, "creating tcp listen socket %d with the existence"
            " of tcp peer listen sockets", SOCKET_GET_ID(sk));
    }

    if (unlikely(0 != (err = socket_listen_socket_insert(sk)))) {
        return err;
    }

    s_tcp_listen_socket_cnt++;

    tcp_listen_init_state(pcb, TCP_LISTEN);
    return 0;
}

static int tcp_listen_socket_get_opt(socket_t *sk,
    lune_socket_opt_en opt, unsigned char *opt_val, unsigned int opt_len)
{
    tcp_listen_pcb_t *pcb = &sk->pcb.tcp_listen;

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
    case LUNE_SOCKET_OPT_GET_TCP_MSS:
        if (unlikely(NULL == opt_val || opt_len != sizeof(unsigned short))) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        if (NULL == pcb->ipp) {
            return ERR_SET_ERR(LUNE_ERR_NOT_BOUND);
        }

        *(unsigned short *)opt_val = pcb->init_mss;
        break;
    default:
        return ERR_SET_ERR(LUNE_ERR_OPT_NOT_FOUND);
    }

    return 0;
}

static int tcp_listen_socket_set_opt(socket_t *sk,
    lune_socket_opt_en opt, const unsigned char *opt_val, unsigned int opt_len)
{
    tcp_listen_pcb_t *pcb = &sk->pcb.tcp_listen;
    tcp_pcb_t *p;

    switch (opt) {
    case LUNE_SOCKET_OPT_SET_CALLBACK:
        if (NULL == opt_val
            || opt_len != sizeof(lune_tcp_socket_callback_t)) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        if (NULL != ((const lune_tcp_socket_callback_t *)opt_val)->connect) {
            lune_log(LUNE_INFO, "attempted to register connect event"
                " on tcp listen socket %d", SOCKET_GET_ID(sk));
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        memcpy(&pcb->cb, opt_val, sizeof(lune_tcp_socket_callback_t));
        break;
    case LUNE_SOCKET_OPT_SET_CALLBACK_DATA:
        if (NULL == opt_val || opt_len != sizeof(void *)) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        pcb->cb.data = *(void * const *)opt_val;
        break;
    case LUNE_SOCKET_OPT_CLEAR_CALLBACK:
        if (unlikely(NULL != opt_val || 0 != opt_len)) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        memset(&pcb->cb, 0x00, sizeof(lune_tcp_socket_callback_t));
        break;
    case LUNE_SOCKET_OPT_SET_TCP_MSS:
    {
        unsigned short max_mss;

        if (NULL == opt_val
            || opt_len != sizeof(unsigned short)) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        if (NULL == pcb->ipp) {
            /* mss can only be set after bind */
            return ERR_SET_ERR(LUNE_ERR_NOT_BOUND);
        }

        max_mss = tcp_listen_get_max_mss(pcb);
        if (*(const unsigned short *)opt_val > max_mss) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        pcb->init_mss = *(const unsigned short *)opt_val;
        pcb->init_cwnd = pcb->init_mss * TCP_INIT_CWND_SEG_NUM;
        pcb->init_ss_thresh = pcb->init_mss * TCP_INIT_SS_THRESH_SEG_NUM;
        break;
    }
    case LUNE_SOCKET_OPT_SET_NORMAL_CLOSE:
        if (unlikely(NULL != opt_val || 0 != opt_len)) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        if (likely(TCP_GET_CLOSE_TYPE(pcb) != TCP_CLOSE_TYPE_NORMAL)) {
            TCP_SET_NORMAL_CLOSE(pcb);
        } else {
            lune_log(LUNE_INFO, "normal closure already set for tcp listen socket %d",
                SOCKET_GET_ID(sk));
        }

        break;
    case LUNE_SOCKET_OPT_SET_RST_CLOSE:
        if (unlikely(NULL != opt_val || 0 != opt_len)) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        if (likely(TCP_GET_CLOSE_TYPE(pcb) != TCP_CLOSE_TYPE_RST)) {
            TCP_SET_RST_CLOSE(pcb);
        } else {
            lune_log(LUNE_INFO, "reset closure already set for tcp listen socket %d",
                SOCKET_GET_ID(sk));
        }

        break;
    case LUNE_SOCKET_OPT_SET_QUIET_CLOSE:
        if (unlikely(NULL != opt_val || 0 != opt_len)) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        if (likely(TCP_GET_CLOSE_TYPE(pcb) != TCP_CLOSE_TYPE_QUIET)) {
            TCP_SET_QUIET_CLOSE(pcb);
        } else {
            lune_log(LUNE_INFO, "quiet closure already set for tcp listen socket %d",
                SOCKET_GET_ID(sk));
        }

        break;
    case LUNE_SOCKET_OPT_SET_TCP_ZERO_WIN:
        if (unlikely(NULL != opt_val || 0 != opt_len)) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        if (unlikely(TCP_ZERO_WIN_ON(pcb))) {
            return ERR_SET_ERR(LUNE_ERR_ALREADY_SET);
        }

        TCP_ZERO_WIN_TURN_ON(pcb);
        dlist_for_each_node(p, &pcb->backlog_list, node) {
            TCP_ZERO_WIN_TURN_ON(p);
            p->recv_wnd = 0;
        }

        break;
    case LUNE_SOCKET_OPT_CLEAR_TCP_ZERO_WIN:
        if (unlikely(NULL != opt_val || 0 != opt_len)) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        if (unlikely(!TCP_ZERO_WIN_ON(pcb))) {
            return ERR_SET_ERR(LUNE_ERR_NOT_SET);
        }

        TCP_ZERO_WIN_TURN_OFF(pcb);
        dlist_for_each_node(p, &pcb->backlog_list, node) {
            TCP_ZERO_WIN_TURN_OFF(p);
            lune_assert(0 == p->recv_wnd);
            p->recv_wnd = TCP_DEFAULT_WND_SIZE;
        }

        break;
    case LUNE_SOCKET_OPT_SET_TCP_KEEP_ALIVE:
    {
        const lune_tcp_socket_keep_alive_param_t *keep_alive;

        if (unlikely(NULL == opt_val || opt_len != sizeof(lune_tcp_socket_keep_alive_param_t))) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        keep_alive = (const lune_tcp_socket_keep_alive_param_t *)opt_val;
        if (keep_alive->time > LUNE_TCP_SOCKET_KEEP_ALIVE_MAX_TIME
            || keep_alive->intvl < LUNE_TCP_SOCKET_KEEP_ALIVE_MIN_INTVL
            || keep_alive->intvl > LUNE_TCP_SOCKET_KEEP_ALIVE_MAX_INTVL
            || keep_alive->probes < LUNE_TCP_SOCKET_KEEP_ALIVE_MIN_PROBES) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        pcb->keep_alive.time = keep_alive->time;
        pcb->keep_alive.intvl = keep_alive->intvl;
        pcb->keep_alive.probes = keep_alive->probes;

        TCP_KEEP_ALIVE_TURN_ON(pcb);
        break;
    }
    case LUNE_SOCKET_OPT_CLEAR_TCP_KEEP_ALIVE:
        if (!TCP_KEEP_ALIVE_ON(pcb)) {
            return ERR_SET_ERR(LUNE_ERR_NOT_SET);
        }

        TCP_KEEP_ALIVE_TURN_OFF(pcb);
        break;
    case LUNE_SOCKET_OPT_SET_TCP_DELACK:
        if (unlikely(NULL != opt_val || 0 != opt_len)) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        if (TCP_DELACK_ON(pcb)) {
            return ERR_SET_ERR(LUNE_ERR_ALREADY_SET);
        }

        TCP_DELACK_TURN_ON(pcb);
        break;
    case LUNE_SOCKET_OPT_CLEAR_TCP_DELACK:
        if (unlikely(NULL != opt_val || 0 != opt_len)) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        if (!TCP_DELACK_ON(pcb)) {
            return ERR_SET_ERR(LUNE_ERR_NOT_SET);
        }

        TCP_DELACK_TURN_OFF(pcb);
        break;
    case LUNE_SOCKET_OPT_SET_TCP_DELACK_INTVL:
    {
        unsigned int intvl;

        if (NULL == opt_val
            || opt_len != sizeof(unsigned int)) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        intvl = *(const unsigned int *)opt_val;
        if (0 == intvl || intvl > LUNE_TCP_MAX_DELACK_INTVL) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        pcb->delack_intvl = intvl * LUNE_TIME_MILLISECOND;
        break;
    }
    default:
        return ERR_SET_ERR(LUNE_ERR_OPT_NOT_FOUND);
    }

    return 0;
}

static unsigned int tcp_listen_socket_hash(socket_pcb_un *pcb)
{
    return IP_IS_IPV6(pcb->tcp_listen.ipp)
        ? (((lune_ntohl(pcb->tcp_listen.ipp->ipv6.ip.addr[3]) << 12)
        | (pcb->tcp_listen.port & 0xfff)) & SOCKET_LISTEN_HTABLE_MASK)
        : (((pcb->tcp_listen.ipp->ipv4.ip << 12) | (pcb->tcp_listen.port & 0xfff)) & SOCKET_LISTEN_HTABLE_MASK);
}

static int tcp_listen_socket_compare(socket_pcb_un *pcb1, socket_pcb_un *pcb2)
{
    return (pcb1->tcp_listen.ipp == pcb2->tcp_listen.ipp
        && pcb1->tcp_listen.port == pcb2->tcp_listen.port) ? 0 : 1;
}

socket_ops_t g_socket_ops_tcp_listen = {
    .create = (socket_create_func_t)tcp_listen_socket_create,
    .bind = (socket_bind_func_t)tcp_listen_socket_bind,
    .connect = NULL,
    .listen = (socket_listen_func_t)tcp_listen_socket_listen,
    .send = NULL,
    .send_pkts = NULL,
    .sendto = NULL,
    .get_opt = (socket_get_opt_func_t)tcp_listen_socket_get_opt,
    .set_opt = (socket_set_opt_func_t)tcp_listen_socket_set_opt,
    .close = (socket_close_func_t)tcp_listen_socket_close,
    .hash = (socket_hash_func_t)tcp_listen_socket_hash,
    .compare = (socket_compare_func_t)tcp_listen_socket_compare,
    .get_max_hdr_len = NULL,
};

static int tcp_batch_listen_socket_create(socket_t *listen_sk)
{
    tcp_listen_pcb_t *listen_pcb = &listen_sk->pcb.tcp_listen;

    dlist_init_head(&listen_pcb->backlog_list);
    listen_pcb->ipp = NULL;
    listen_pcb->ifp = NULL;
    listen_pcb->state = TCP_CLOSED;
    listen_pcb->port = listen_pcb->end_port = 0;
    listen_pcb->flags = TCP_DELACK_FLAG;
    listen_pcb->delack_intvl = TCP_DEFAULT_DELACK_INTVL;
    listen_pcb->jiffies = TIMER_GET_CURRENT_JIFFIES();
    listen_pcb->backlog = LUNE_TCP_LISTEN_BACKLOG_UNLIMITED;
    listen_pcb->backlog_cnt = 0;
    memset(&listen_pcb->cb, 0x00, sizeof(lune_tcp_socket_callback_t));

    return 0;
}

static int tcp_batch_listen_socket_bind(socket_t *sk, const void *arg, unsigned int arg_len)
{
    ip_t *ipp;
    tcp_listen_pcb_t *pcb;

    if (arg_len != sizeof(lune_socket_batch_listen_addr_t)
        || (((const lune_socket_batch_listen_addr_t *)arg)->start_port
        > ((const lune_socket_batch_listen_addr_t *)arg)->end_port)) {
        return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
    }

    pcb = &sk->pcb.tcp_listen;
    if (NULL != pcb->ipp) {
        return ERR_SET_ERR(LUNE_ERR_ALREADY_BOUND);
    }

    if (NULL == (ipp = ip_get_ip_by_id(((const lune_socket_batch_listen_addr_t *)arg)->id))) {
        return ERR_SET_ERR(LUNE_ERR_ID_NOT_FOUND);
    }

    if (IP_IS_SOCKET(ipp)) {
        return ERR_SET_ERR(LUNE_ERR_ALREADY_BOUND);
    }

    pcb->ipp = ipp;
    ip_hold(ipp);
    /* ipv4 or ipv6 not matter, will return the interface for ip */
    pcb->ifp = net_if_get_net_if_by_entry(LUNE_ID_IPV4, ipp);
    if (likely(NULL != pcb->ifp)) {
        net_if_hold(pcb->ifp);
    }
    pcb->port = ((const lune_socket_batch_listen_addr_t *)arg)->start_port;
    pcb->end_port = ((const lune_socket_batch_listen_addr_t *)arg)->end_port;

    pcb->init_mss = tcp_listen_get_max_mss(pcb);
    pcb->init_cwnd = pcb->init_mss * TCP_INIT_CWND_SEG_NUM;
    pcb->init_ss_thresh = pcb->init_mss * TCP_INIT_SS_THRESH_SEG_NUM;

    IP_SET_L4_SOCKET(ipp);

    sk->rsvd_hdr_len = tcp_listen_socket_get_max_hdr_len(pcb);

    return 0;
}

static int tcp_batch_listen_socket_listen(socket_t *sk, unsigned int backlog)
{
    tcp_listen_pcb_t *pcb = &sk->pcb.tcp_listen;
    int err;

    if (NULL == pcb->ipp) {
        return ERR_SET_ERR(LUNE_ERR_NOT_BOUND);
    }

    if (LUNE_TCP_LISTEN_BACKLOG_UNLIMITED != backlog
        && (backlog / (pcb->end_port - pcb->port + 1)) > LUNE_TCP_LISTEN_MAX_BACKLOG) {
        return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
    }

    pcb->backlog = backlog;

    if (s_tcp_listen_socket_cnt > 0
        || s_tcp_peer_listen_socket_cnt > 0) {
        /*
            unable to detect if a listen socket or peer listen
            socket has been established on the same <local ip,
            local port>. just log and move on
        */
        lune_log_once(LUNE_DBG, "creating tcp batch listen socket %d with the existence"
            " of tcp (peer) listen sockets", SOCKET_GET_ID(sk));
    }

    if (unlikely(0 != (err = socket_listen_socket_insert(sk)))) {
        return err;
    }

    s_tcp_batch_listen_socket_cnt++;

    tcp_listen_init_state(pcb, TCP_LISTEN);
    return 0;
}

static unsigned int tcp_batch_listen_socket_hash(socket_pcb_un *pcb)
{
    return IP_IS_IPV6(pcb->tcp_listen.ipp)
        ? (lune_ntohl(pcb->tcp_listen.ipp->ipv6.ip.addr[3]) & SOCKET_LISTEN_HTABLE_MASK)
        : (pcb->tcp_listen.ipp->ipv4.ip & SOCKET_LISTEN_HTABLE_MASK);
}

static int tcp_batch_listen_socket_compare(socket_pcb_un *pcb1, socket_pcb_un *pcb2)
{
    return (pcb1->tcp_listen.ipp == pcb2->tcp_listen.ipp
        && ((pcb1->tcp_listen.port <= pcb2->tcp_listen.port
        && pcb1->tcp_listen.end_port >= pcb2->tcp_listen.port)
        || (pcb2->tcp_listen.end_port != 0
        && pcb1->tcp_listen.port <= pcb2->tcp_listen.end_port
        && pcb1->tcp_listen.end_port >= pcb2->tcp_listen.end_port))) ? 0 : 1;
}

socket_ops_t g_socket_ops_tcp_batch_listen = {
    .create = (socket_create_func_t)tcp_batch_listen_socket_create,
    .bind = (socket_bind_func_t)tcp_batch_listen_socket_bind,
    .connect = NULL,
    .listen = (socket_listen_func_t)tcp_batch_listen_socket_listen,
    .send = NULL,
    .send_pkts = NULL,
    .sendto = NULL,
    .get_opt = (socket_get_opt_func_t)tcp_listen_socket_get_opt,
    .set_opt = (socket_set_opt_func_t)tcp_listen_socket_set_opt,
    .close = (socket_close_func_t)tcp_listen_socket_close,
    .hash = (socket_hash_func_t)tcp_batch_listen_socket_hash,
    .compare = (socket_compare_func_t)tcp_batch_listen_socket_compare,
    .get_max_hdr_len = NULL,
};

static int tcp_peer_listen_socket_create(socket_t *listen_sk)
{
    tcp_listen_pcb_t *listen_pcb = &listen_sk->pcb.tcp_listen;

    dlist_init_head(&listen_pcb->backlog_list);
    listen_pcb->ipp = NULL;
    listen_pcb->ifp = NULL;
    listen_pcb->state = TCP_CLOSED;
    listen_pcb->port = 0;
    LUNE_IP_INIT(&listen_pcb->peer_addr);
    listen_pcb->flags = TCP_DELACK_FLAG;
    listen_pcb->delack_intvl = TCP_DEFAULT_DELACK_INTVL;
    listen_pcb->jiffies = TIMER_GET_CURRENT_JIFFIES();
    listen_pcb->backlog = LUNE_TCP_LISTEN_BACKLOG_UNLIMITED;
    listen_pcb->backlog_cnt = 0;
    memset(&listen_pcb->cb, 0x00, sizeof(lune_tcp_socket_callback_t));

    return 0;
}

static int tcp_peer_listen_socket_bind(socket_t *sk, const void *arg, unsigned int arg_len)
{
    ip_t *ipp;
    tcp_listen_pcb_t *pcb;

    if (arg_len != sizeof(lune_socket_peer_listen_addr_t)) {
        return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
    }

    pcb = &sk->pcb.tcp_listen;
    if (NULL != pcb->ipp) {
        return ERR_SET_ERR(LUNE_ERR_ALREADY_BOUND);
    }

    if (NULL == (ipp = ip_get_ip_by_id(((const lune_socket_peer_listen_addr_t *)arg)->id))) {
        return ERR_SET_ERR(LUNE_ERR_ID_NOT_FOUND);
    }

    if (IP_IS_SOCKET(ipp)) {
        return ERR_SET_ERR(LUNE_ERR_ALREADY_BOUND);
    }

    pcb->ipp = ipp;
    ip_hold(ipp);
    /* ipv4 or ipv6 not matter, will return the interface for ip */
    pcb->ifp = net_if_get_net_if_by_entry(LUNE_ID_IPV4, ipp);
    if (likely(NULL != pcb->ifp)) {
        net_if_hold(pcb->ifp);
    }
    pcb->port = ((const lune_socket_peer_listen_addr_t *)arg)->port;
    pcb->peer_addr = ((const lune_socket_peer_listen_addr_t *)arg)->peer_addr;

    pcb->init_mss = tcp_listen_get_max_mss(pcb);
    pcb->init_cwnd = pcb->init_mss * TCP_INIT_CWND_SEG_NUM;
    pcb->init_ss_thresh = pcb->init_mss * TCP_INIT_SS_THRESH_SEG_NUM;

    IP_SET_L4_SOCKET(ipp);

    sk->rsvd_hdr_len = tcp_listen_socket_get_max_hdr_len(pcb);

    return 0;
}

static int tcp_peer_listen_socket_listen(socket_t *sk, unsigned int backlog)
{
    tcp_listen_pcb_t *pcb = &sk->pcb.tcp_listen;
    socket_t psd_sk;
    int err;

    if (NULL == pcb->ipp) {
        return ERR_SET_ERR(LUNE_ERR_NOT_BOUND);
    }

    if (backlog > LUNE_TCP_LISTEN_MAX_BACKLOG) {
        return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
    }

    pcb->backlog = backlog;

    if (s_tcp_batch_listen_socket_cnt > 0) {
        psd_sk.type = LUNE_SOCKET_TCP_BATCH_LISTEN;
        psd_sk.ops = &g_socket_ops_tcp_batch_listen;
        psd_sk.pcb.tcp_listen.ipp = pcb->ipp;
        psd_sk.pcb.tcp_listen.port = pcb->port;
        psd_sk.pcb.tcp_listen.end_port = 0;
        if (NULL != socket_listen_socket_find(&psd_sk)) {
            return ERR_SET_ERR(LUNE_ERR_ALREADY_BOUND);
        }
    }

    if (s_tcp_listen_socket_cnt > 0) {
        psd_sk.type = LUNE_SOCKET_TCP_LISTEN;
        psd_sk.ops = &g_socket_ops_tcp_listen;
        psd_sk.pcb.tcp_listen.ipp = pcb->ipp;
        psd_sk.pcb.tcp_listen.port = pcb->port;
        if (NULL != socket_listen_socket_find(&psd_sk)) {
            return ERR_SET_ERR(LUNE_ERR_ALREADY_BOUND);
        }
    }

    if (unlikely(0 != (err = socket_listen_socket_insert(sk)))) {
        return err;
    }

    s_tcp_peer_listen_socket_cnt++;

    tcp_listen_init_state(pcb, TCP_LISTEN);
    return 0;
}

static int tcp_peer_listen_socket_compare(socket_pcb_un *pcb1, socket_pcb_un *pcb2)
{
    return (pcb1->tcp_listen.ipp == pcb2->tcp_listen.ipp
        && pcb1->tcp_listen.port == pcb2->tcp_listen.port
        && (!LUNE_IP_CMP(&pcb1->tcp_listen.peer_addr, &pcb2->tcp_listen.peer_addr))) ? 0 : 1;
}

socket_ops_t g_socket_ops_tcp_peer_listen = {
    .create = (socket_create_func_t)tcp_peer_listen_socket_create,
    .bind = (socket_bind_func_t)tcp_peer_listen_socket_bind,
    .connect = NULL,
    .listen = (socket_listen_func_t)tcp_peer_listen_socket_listen,
    .send = NULL,
    .send_pkts = NULL,
    .sendto = NULL,
    .get_opt = (socket_get_opt_func_t)tcp_listen_socket_get_opt,
    .set_opt = (socket_set_opt_func_t)tcp_listen_socket_set_opt,
    .close = (socket_close_func_t)tcp_listen_socket_close,
    .hash = (socket_hash_func_t)tcp_listen_socket_hash,
    .compare = (socket_compare_func_t)tcp_peer_listen_socket_compare,
    .get_max_hdr_len = NULL,
};
