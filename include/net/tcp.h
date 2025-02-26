/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2024 Lune Reseau, Inc.
 */

#ifndef __TCP_H_PRE__
#define __TCP_H_PRE__

#include "lune/ip.h"
#include "lune/tcp.h"

#include "net/ip.h"
#include "net/pbuf.h"
#include "net/socket.h"

/* DON'T CHANGE ORDER */
typedef enum _tcp_state {
    TCP_SYNR = 0,
    TCP_SYNS = 1,
    TCP_EST = 2,
    TCP_FINWT1 = 3,
    TCP_FINWT2 = 4,
    TCP_CLOSING = 5,
    TCP_TWAIT = 6,
    TCP_CLWAIT = 7,
    TCP_LASTACK = 8,
    TCP_LISTEN = 9,
    TCP_CLOSED = 10,    /* MUST be the last */
} tcp_state_en;

typedef struct _tcp_pcb {
    dlist_node_t node;  /* backlog list node */

    ip_t *ipp;
    void *ifp;     /* for statistics only */
    lune_ip_addr_t dst_ip;
    unsigned short src_port;
    unsigned short dst_port;

#define TCP_FLAG_ON(pcb, flag)              ((pcb)->flags & (flag))
#define TCP_SET_FLAG(pcb, flag)             \
    do { (pcb)->flags |= (flag); } while (0)
#define TCP_CLEAR_FLAG(pcb, flag)           \
    do { (pcb)->flags &= (~flag); } while (0)
#define TCP_MASK_CLOSE_TYPE                 0x0003
#define TCP_CLOSE_TYPE_NORMAL               0x0000
#define TCP_CLOSE_TYPE_RST                  0x0001
/* TCP_CLOSE_TYPE_QUIET: close connection without signaling the peer */
#define TCP_CLOSE_TYPE_QUIET                0x0002
#define TCP_GET_CLOSE_TYPE(pcb)             ((pcb)->flags & TCP_MASK_CLOSE_TYPE)
#define TCP_SET_CLOSE_TYPE(pcb, type)       \
    do { (pcb)->flags =                     \
        ((pcb)->flags & (~TCP_MASK_CLOSE_TYPE)) | (type); } while (0)
#define TCP_SET_NORMAL_CLOSE(pcb)           \
    TCP_SET_CLOSE_TYPE(pcb, TCP_CLOSE_TYPE_NORMAL)
#define TCP_SET_RST_CLOSE(pcb)              \
    TCP_SET_CLOSE_TYPE(pcb, TCP_CLOSE_TYPE_RST)
#define TCP_SET_QUIET_CLOSE(pcb)            \
    TCP_SET_CLOSE_TYPE(pcb, TCP_CLOSE_TYPE_QUIET)
#define TCP_ACK_NOT_SENT_FLAG               0x0004
#define TCP_ACK_IS_SENT(pcb)                (!TCP_FLAG_ON(pcb, TCP_ACK_NOT_SENT_FLAG))
#define TCP_ACK_SENT_SET_FLAG(pcb)          TCP_CLEAR_FLAG(pcb, TCP_ACK_NOT_SENT_FLAG)
#define TCP_ACK_SENT_CLEAR_FLAG(pcb)        TCP_SET_FLAG(pcb, TCP_ACK_NOT_SENT_FLAG)
#define TCP_ALL_OR_NONE_XMIT_FLAG           0x0008
#define TCP_ALL_OR_NONE_XMIT_ON(pcb)        TCP_FLAG_ON(pcb, TCP_ALL_OR_NONE_XMIT_FLAG)
#define TCP_ALL_OR_NONE_XMIT_TURN_ON(pcb)   TCP_SET_FLAG(pcb, TCP_ALL_OR_NONE_XMIT_FLAG)
#define TCP_ALL_OR_NONE_XMIT_TURN_OFF(pcb)  TCP_CLEAR_FLAG(pcb, TCP_ALL_OR_NONE_XMIT_FLAG)
#define TCP_DELACK_FLAG                     0x0010
#define TCP_DELACK_ON(pcb)                  TCP_FLAG_ON(pcb, TCP_DELACK_FLAG)
#define TCP_DELACK_TURN_ON(pcb)             TCP_SET_FLAG(pcb, TCP_DELACK_FLAG)
#define TCP_DELACK_TURN_OFF(pcb)            TCP_CLEAR_FLAG(pcb, TCP_DELACK_FLAG)
#define TCP_ZERO_WIN_FLAG                   0x0020
#define TCP_ZERO_WIN_ON(pcb)                TCP_FLAG_ON(pcb, TCP_ZERO_WIN_FLAG)
#define TCP_ZERO_WIN_TURN_ON(pcb)           TCP_SET_FLAG(pcb, TCP_ZERO_WIN_FLAG)
#define TCP_ZERO_WIN_TURN_OFF(pcb)          TCP_CLEAR_FLAG(pcb, TCP_ZERO_WIN_FLAG)
#define TCP_EST_ZERO_WIN_FLAG               0x0040
#define TCP_EST_IS_ZERO_WIN(pcb)            TCP_FLAG_ON(pcb, TCP_EST_ZERO_WIN_FLAG)
#define TCP_SET_EST_ZERO_WIN(pcb)           TCP_SET_FLAG(pcb, TCP_EST_ZERO_WIN_FLAG)
#define TCP_CLEAR_EST_ZERO_WIN(pcb)         TCP_CLEAR_FLAG(pcb, TCP_EST_ZERO_WIN_FLAG)
#define TCP_KEEP_ALIVE_FLAG                 0x0080
#define TCP_KEEP_ALIVE_ON(pcb)              TCP_FLAG_ON(pcb, TCP_KEEP_ALIVE_FLAG)
#define TCP_KEEP_ALIVE_TURN_ON(pcb)         TCP_SET_FLAG(pcb, TCP_KEEP_ALIVE_FLAG)
#define TCP_KEEP_ALIVE_TURN_OFF(pcb)        TCP_CLEAR_FLAG(pcb, TCP_KEEP_ALIVE_FLAG)
#define TCP_EST_FASTACK_FLAG                0x0100
#define TCP_EST_FASTACK_ON(pcb)             TCP_FLAG_ON(pcb, TCP_EST_FASTACK_FLAG)
#define TCP_EST_FASTACK_TURN_ON(pcb)        TCP_SET_FLAG(pcb, TCP_EST_FASTACK_FLAG)
#define TCP_EST_FASTACK_TURN_OFF(pcb)       TCP_CLEAR_FLAG(pcb, TCP_EST_FASTACK_FLAG)
    unsigned short flags;

    /* maximum segment size */
    unsigned short mss;
    /* congestion avoidance/control variables */
    unsigned short cwnd;
    /* slow start thresh */
    unsigned short ss_thresh;

    /* retransmit timer */
    lune_timer_t retrans_tmr;
    /* delay-ACK timer */
    lune_timer_t delack_tmr;
    union {
        /* time-wait timer */
        lune_timer_t time_wait_tmr;
        /* delay-RST timer */
        lune_timer_t delay_rst_tmr;
    };
    /* keep-alive timer */
    lune_timer_t keep_alive_tmr;

    unsigned int last_ack;
    /* next sequence number expected to receive */
    unsigned int recv_nxt;
    /* send last buffer beginning */
    unsigned int send_lbb;
    /* sender window */
    unsigned short send_wnd;
    /* receiver window */
    unsigned short recv_wnd;

    /* keep-alive parameters, initialized only when set */
    lune_tcp_socket_keep_alive_param_t keep_alive;
    unsigned int keep_alive_probes;

    /* delay-ACK interval in ms */
    unsigned int delack_intvl;

    tcp_state_en state;

    unsigned long long jiffies;

    unsigned long long close_start_jiffies;
    unsigned long long est_start_jiffies;
    unsigned long long resp_start_jiffies;
    unsigned long long setup_start_jiffies;

    dlist_head_t send_buf_list;
    dlist_head_t unack_buf_list;
    dlist_head_t unordered_buf_list;

    lune_tcp_socket_callback_t cb;

#define TCP_IS_SERVER_SOCKET(pcb)           (NULL != (pcb)->listen_sk)
    /* for establishment of server socket only. once it's established, set to -1 */
    socket_t *listen_sk;
} tcp_pcb_t;

typedef struct _tcp_listen_pcb {
    dlist_head_t backlog_list;

    ip_t *ipp;
    void *ifp;                     /* for statistics only */

    tcp_state_en state;

    unsigned short port;
    union {
        unsigned short end_port;    /* for batch listen only */
        lune_ip_addr_t peer_addr;   /* for peer listen only */
    };

    /* mss, cwnd and ss_thresh */
    unsigned short init_mss;
    unsigned short init_cwnd;
    unsigned short init_ss_thresh;

    unsigned short flags;           /* the same as flags field in tcp_pcb_t */

    /* keep-alive parameters */
    lune_tcp_socket_keep_alive_param_t keep_alive;

    unsigned int delack_intvl;

    unsigned long long jiffies;

    unsigned int backlog;
    unsigned int backlog_cnt;

    lune_tcp_socket_callback_t cb;
} tcp_listen_pcb_t;

#endif

#ifndef __TCP_H__
#define __TCP_H__

#define TCP_SEQ_EQ(a,b)             ((int)(((unsigned int)a) - ((unsigned int)b)) == 0)
#define TCP_SEQ_NEQ(a,b)            ((int)(((unsigned int)a) - ((unsigned int)b)) != 0)
#define TCP_SEQ_LT(a,b)             ((int)(((unsigned int)a) - ((unsigned int)b)) < 0)
#define TCP_SEQ_LEQ(a,b)            ((int)(((unsigned int)a) - ((unsigned int)b)) <= 0)
#define TCP_SEQ_GT(a,b)             ((int)(((unsigned int)a) - ((unsigned int)b)) > 0)
#define TCP_SEQ_GEQ(a,b)            ((int)(((unsigned int)a) - ((unsigned int)b)) >= 0)
#define TCP_SEQ_VAL(a, b)           ((int)(((unsigned int)a) - ((unsigned int)b)))

#define TCP_GET_STATE_STR(state)    (g_tcp_state_str[state])

#define TCP_INIT_CWND_SEG_NUM       (4)
#define TCP_INIT_SS_THRESH_SEG_NUM  (16)

static inline unsigned int tcp_get_data_room(tcp_pcb_t *pcb)
{
    unsigned int eff_cwnd, sent;

    eff_cwnd = (pcb->cwnd > pcb->send_wnd) ? pcb->send_wnd : pcb->cwnd;
    sent = TCP_SEQ_VAL(pcb->send_lbb, pcb->last_ack);
    if (unlikely(eff_cwnd <= sent)) {
        /* congestion window full, maybe too much data is being sent in burst */
        return 0;
    }

    return eff_cwnd - sent;
}

extern const char *g_tcp_state_str[];

extern socket_ops_t g_socket_ops_tcp;
extern socket_ops_t g_socket_ops_tcp_listen;
extern socket_ops_t g_socket_ops_tcp_batch_listen;
extern socket_ops_t g_socket_ops_tcp_peer_listen;

char *tcp_print_pcb_4tuple(tcp_pcb_t *pcb);

unsigned short tcp_get_max_mss(tcp_pcb_t *pcb);
unsigned short tcp_listen_get_max_mss(tcp_listen_pcb_t *pcb);

int tcp_local_init(void);
void tcp_local_fini(void);

int tcp_input(ip_t *ipp, const void *iph, pbuf_t *pbuf);

#endif