/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2024 Lune Reseau, Inc.
 */

#include "lune/atomic.h"
#include "lune/log.h"
#include "lune/mem.h"
#include "lune/net_if.h"
#include "lune/os/linux.h"

#include "drv/net_if_virt.h"
#include "kernel/sched.h"
#include "lib/htable.h"
#include "net/socket.h"
#include "rt/core.h"

#define NET_IF_VIRT_IS_CONNECTED(virt)     (NULL != ((net_if_virt_t *)(virt))->peer_virt)
#define NET_IF_VIRT_DEFAULT_MTU            (1500)
#define NET_IF_VIRT_BUF_SIZE_IN_BIT        (27)
#define NET_IF_VIRT_BUF_SIZE               (1 << NET_IF_VIRT_BUF_SIZE_IN_BIT)
/* NOTICE: maximum packet size 2k */
#define NET_IF_VIRT_PKT_SIZE_IN_BIT        (11)
#define NET_IF_VIRT_PKT_SIZE               (1 << NET_IF_VIRT_PKT_SIZE_IN_BIT)
#define NET_IF_VIRT_PKT_NUM_IN_BIT         (NET_IF_VIRT_BUF_SIZE_IN_BIT - NET_IF_VIRT_PKT_SIZE_IN_BIT)
#define NET_IF_VIRT_PKT_NUM                (1 << NET_IF_VIRT_PKT_NUM_IN_BIT)
#define NET_IF_VIRT_GET_NEXT_PKT_IDX(idx)  (((idx) + 1) % NET_IF_VIRT_PKT_NUM)
#define NET_IF_VIRT_GET_PREV_PKT_IDX(idx)  (((idx) + NET_IF_VIRT_PKT_NUM - 1) % NET_IF_VIRT_PKT_NUM)

#define NET_IF_VIRT_HTABLE_SIZE_IN_BIT     (8)
#define NET_IF_VIRT_HTABLE_SIZE            (1 << (NET_IF_VIRT_HTABLE_SIZE_IN_BIT))
#define NET_IF_VIRT_HTABLE_MASK            (NET_IF_VIRT_HTABLE_SIZE - 1)

typedef struct _net_if_virt {
    dlist_node_t node;
    char name[LUNE_MAX_SHORT_NAME_BUF_LEN];
    unsigned char *send_buf;
    unsigned char *recv_buf;
    lune_net_if_stats_t stats;
    unsigned int send_idx;
    unsigned int recv_idx;
    unsigned short mtu;
    lune_atomic16_t ref_cnt;
    unsigned int core_id;
    unsigned int id;
    lune_atomic32_t conn_cnt;
    net_if_conn_type_en conn_type;
    net_if_t *ifp;
    struct _net_if_virt *peer_virt;
} net_if_virt_t;

#pragma pack(1)
typedef struct _net_if_virt_pkt_hdr {
#define NET_IF_VIRT_PKT_WRITABLE           (0)
#define NET_IF_VIRT_PKT_WRITING            (1)
#define NET_IF_VIRT_PKT_READABLE           (2)
#define NET_IF_VIRT_PKT_READING            (3)
#define NET_IF_VIRT_IS_PKT_WRITABLE(hdr)   (((net_if_virt_pkt_hdr_t *)(hdr))->flag == NET_IF_VIRT_PKT_WRITABLE)
#define NET_IF_VIRT_IS_PKT_READABLE(hdr)   (((net_if_virt_pkt_hdr_t *)(hdr))->flag == NET_IF_VIRT_PKT_READABLE)
#define NET_IF_VIRT_SET_PKT_WRITING(hdr)   \
    do { (((net_if_virt_pkt_hdr_t *)(hdr))->flag = NET_IF_VIRT_PKT_WRITING); } while (0)
#define NET_IF_VIRT_SET_PKT_WRITABLE(hdr)  \
    do { (((net_if_virt_pkt_hdr_t *)(hdr))->flag = NET_IF_VIRT_PKT_WRITABLE); } while (0)
#define NET_IF_VIRT_SET_PKT_READABLE(hdr)  \
    do { (((net_if_virt_pkt_hdr_t *)(hdr))->flag = NET_IF_VIRT_PKT_READABLE); } while (0)
#define NET_IF_VIRT_SET_PKT_READING(hdr)   \
    do { (((net_if_virt_pkt_hdr_t *)(hdr))->flag = NET_IF_VIRT_PKT_READING); } while (0)
    int flag;
    int len;
    unsigned char buf[0];
} net_if_virt_pkt_hdr_t;
#pragma pack()

static void *s_net_if_virt_htable = NULL;

static void net_if_virt_cleanup_send_buf(unsigned char *buf, unsigned int idx)
{
    net_if_virt_pkt_hdr_t *hdr;

    do {
        idx = NET_IF_VIRT_GET_PREV_PKT_IDX(idx);
        hdr = (net_if_virt_pkt_hdr_t *)(buf
            + (idx << NET_IF_VIRT_PKT_SIZE_IN_BIT));
        if (NET_IF_VIRT_IS_PKT_WRITABLE(hdr)) {
            break;
        }
        NET_IF_VIRT_SET_PKT_WRITABLE(hdr);
    } while (1);
}

static int net_if_virt_init_virt(net_if_virt_t *virt, const char *name, net_if_t *ifp)
{
    if (NULL == (virt->send_buf = lune_malloc_mt(NET_IF_VIRT_BUF_SIZE))) {
        return ERR_GET_LAST_ERR();
    }

    dlist_init_node(&virt->node);
    strcpy(virt->name, name);
    virt->recv_buf = NULL;
    memset(&virt->stats, 0x00, sizeof(lune_net_if_stats_t));
    virt->send_idx = 0;
    virt->recv_idx = 0;
    virt->mtu = NET_IF_VIRT_DEFAULT_MTU;
    lune_atomic16_set(&virt->ref_cnt, 0);
    virt->core_id = CORE_GET_ID();
    virt->id = NET_IF_GET_ID(ifp);
    lune_atomic32_set(&virt->conn_cnt, 0);
    virt->conn_type = NET_IF_CONN_TYPE_NONE;
    virt->ifp = ifp;
    virt->peer_virt = NULL;

    return 0;
}

static void net_if_virt_cleanup_virt(net_if_virt_t *virt)
{
    lune_assert(0 == lune_atomic32_get(&virt->conn_cnt));
    lune_assert(!dlist_node_is_added(&virt->node));

    net_if_virt_cleanup_send_buf(virt->send_buf, virt->send_idx);

    lune_free_mt(virt->send_buf);
    virt->send_buf = NULL;
}

static void net_if_virt_hold(net_if_virt_t *virt)
{
#ifdef LUNE_DEBUG
    lune_assert(lune_atomic16_get(&virt->ref_cnt) >= 0);
#endif
    lune_atomic16_inc(&virt->ref_cnt);
}

static void net_if_virt_put(net_if_virt_t *virt)
{
#ifdef LUNE_DEBUG
    lune_assert(lune_atomic16_get(&virt->ref_cnt) > 0);
#endif
    if (lune_atomic16_dec_is_zero(&virt->ref_cnt)) {
        net_if_virt_cleanup_virt(virt);
        lune_free_mt(virt);
    }
}

static int net_if_virt_hash(net_if_virt_t *virt)
{
    return (virt->id) & NET_IF_VIRT_HTABLE_MASK;
}

static int net_if_virt_compare(net_if_virt_t *virt1, net_if_virt_t *virt2)
{
    return (!(virt1->core_id == virt2->core_id && virt1->id == virt2->id));
}

int net_if_virt_init(void)
{
    if (NULL == (s_net_if_virt_htable = htable_create_table_mt("virtual interface hash table across threads", 
        (htable_hash_func_t)net_if_virt_hash,
        (htable_compare_func_t)net_if_virt_compare,
        (htable_hold_func_t)net_if_virt_hold,
        (htable_put_func_t)net_if_virt_put,
        offsetof(net_if_virt_t, node),
        NET_IF_VIRT_HTABLE_SIZE))) {
        return ERR_GET_LAST_ERR();
    }

    return 0;
}

void net_if_virt_fini(void)
{
    lune_assert(!htable_delete_table_mt(s_net_if_virt_htable));
    s_net_if_virt_htable = NULL;
}

static void net_if_virt_connect_virt(net_if_virt_t *virt, net_if_virt_t *peer_virt, unsigned int local)
{
    virt->recv_buf = peer_virt->send_buf;
    virt->peer_virt = peer_virt;
    virt->conn_type = local ? NET_IF_CONN_TYPE_LOCAL : NET_IF_CONN_TYPE_REMOTE_ACTIVE;
    peer_virt->recv_buf = virt->send_buf;
    peer_virt->peer_virt = virt;
    peer_virt->conn_type = local ? NET_IF_CONN_TYPE_LOCAL : NET_IF_CONN_TYPE_REMOTE_PASSIVE;
}

static void net_if_virt_disconnect_virt(net_if_virt_t *virt)
{
    net_if_virt_t *peer_virt = virt->peer_virt;

    lune_assert(NULL != peer_virt);

    virt->recv_buf = NULL;
    virt->peer_virt = NULL;
    virt->conn_type = NET_IF_CONN_TYPE_NONE;
    peer_virt->recv_buf = NULL;
    peer_virt->peer_virt = NULL;
    peer_virt->conn_type = NET_IF_CONN_TYPE_NONE;
}

static int net_if_virt_add_net_if(net_if_t *ifp,
    const char *name, const void *conf_val, unsigned int conf_len, void **pdata)
{
    net_if_virt_t *virt;
    int err;

    if (conf_val != NULL || conf_len != 0) {
        err = ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        goto ERR_1;
    }

    if (NULL == (virt = lune_malloc_mt(sizeof(net_if_virt_t)))) {
        err = ERR_GET_LAST_ERR();
        goto ERR_1;
    }

    if (0 != (err = net_if_virt_init_virt(virt, name, ifp))) {
        goto ERR_2;
    }

    if (0 != (err = htable_insert_mt((void *)virt, s_net_if_virt_htable))) {
        goto ERR_3;
    }

    net_if_virt_hold(virt);
    *pdata = virt;
    return 0;

ERR_3:
    net_if_virt_cleanup_virt(virt);

ERR_2:
    lune_free_mt(virt);

ERR_1:
    return err;
}

static int net_if_virt_del_net_if(net_if_virt_t *virt)
{
    if (NET_IF_VIRT_IS_CONNECTED(virt)) {
        /* disconnect before delete */
        lune_assert(NET_IF_CONN_TYPE_NONE != virt->conn_type);
        return ERR_SET_ERR(LUNE_ERR_NET_IF_ALREADY_CONNECTED);
    }

    lune_assert(!htable_remove_mt((void *)virt, s_net_if_virt_htable));
    net_if_virt_put(virt);
    return 0;
}

static int net_if_virt_send(net_if_virt_t *virt, const unsigned char *buf, unsigned int len)
{
    net_if_virt_pkt_hdr_t *hdr;

    if (unlikely(!NET_IF_VIRT_IS_CONNECTED(virt))) {
        return ERR_SET_ERR(LUNE_ERR_NET_IF_INACTIVE);
    }

    hdr = (net_if_virt_pkt_hdr_t *)(virt->send_buf + (virt->send_idx << NET_IF_VIRT_PKT_SIZE_IN_BIT));
    if (!NET_IF_VIRT_IS_PKT_WRITABLE(hdr)) {
        return ERR_SET_ERR(LUNE_ERR_BUF_FULL);
    }

    memcpy(hdr->buf, buf, len);
    if (len < LUNE_NET_IF_MIN_PKT_SIZE) {
        /* zero pad the remaining bytes */
        memset(hdr->buf + len, 0x00, LUNE_NET_IF_MIN_PKT_SIZE - len);
        len = LUNE_NET_IF_MIN_PKT_SIZE;
    }
    hdr->len = len;
    lune_smp_wmb();
    NET_IF_VIRT_SET_PKT_READABLE(hdr);

    virt->send_idx = NET_IF_VIRT_GET_NEXT_PKT_IDX(virt->send_idx);
    virt->stats.byte_out += len;
    virt->stats.pkt_out++;

    return 0;
}

static int net_if_virt_recv(net_if_virt_t *virt, unsigned char **pbuf, unsigned int *plen)
{
    net_if_virt_pkt_hdr_t *hdr;

    if (unlikely(!NET_IF_VIRT_IS_CONNECTED(virt))) {
        /* ERR_SET_ERR() unneeded */
        return -LUNE_ERR_NET_IF_NO_PKT;
    }

    hdr = (net_if_virt_pkt_hdr_t *)(virt->recv_buf + (virt->recv_idx << NET_IF_VIRT_PKT_SIZE_IN_BIT));
    if (!NET_IF_VIRT_IS_PKT_READABLE(hdr)) {
        /* ERR_SET_ERR() unneeded */
        return -LUNE_ERR_NET_IF_NO_PKT;
    }

    NET_IF_VIRT_SET_PKT_READING(hdr);

    *pbuf = hdr->buf;
    *plen = hdr->len;

    virt->stats.byte_in += hdr->len;
    virt->stats.pkt_in++;

    return 0;
}

static void net_if_virt_recv_done(net_if_virt_t *virt)
{
    net_if_virt_pkt_hdr_t *hdr =
        (net_if_virt_pkt_hdr_t *)(virt->recv_buf + (virt->recv_idx << NET_IF_VIRT_PKT_SIZE_IN_BIT));
    NET_IF_VIRT_SET_PKT_WRITABLE(hdr);
    virt->recv_idx = NET_IF_VIRT_GET_NEXT_PKT_IDX(virt->recv_idx);
}

static void net_if_virt_recv_fwd_pkt(net_if_virt_t *virt, void **pdata)
{
    virt->recv_idx = NET_IF_VIRT_GET_NEXT_PKT_IDX(virt->recv_idx);
    *pdata = NULL;
}

static void net_if_virt_recv_free_pkt(net_if_virt_t *virt __attribute__((unused)),
    unsigned char *buf, void *data)
{
    net_if_virt_pkt_hdr_t *hdr = (net_if_virt_pkt_hdr_t *)(buf - sizeof(net_if_virt_pkt_hdr_t));
    lune_assert(NULL == data);
    NET_IF_VIRT_SET_PKT_WRITABLE(hdr);
}

static int net_if_virt_get_opt(net_if_virt_t *virt,
    net_if_opt_en opt,
    unsigned char *opt_val,
    unsigned int opt_len)
{
    lune_assert(NULL != opt_val);

    switch (opt) {
    case NET_IF_OPT_GET_HW_CSUM:
        if (opt_len != sizeof(unsigned short)) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        *(unsigned short *)opt_val = 0;
        break;
    case NET_IF_OPT_GET_MAX_DATA_RATE:
        /*
            always asked while new interface being added, no need to report error
        */
        return -LUNE_ERR_NOT_SUPPORTED;
    case NET_IF_OPT_GET_MTU:
        if (opt_len != sizeof(unsigned short)) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        *(unsigned short *)opt_val = virt->mtu;
        break;
    case NET_IF_OPT_GET_STATS:
        if (opt_len != sizeof(lune_net_if_stats_t)) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        memcpy(opt_val, &virt->stats, sizeof(lune_net_if_stats_t));
        break;
    case NET_IF_OPT_GET_PEER_NET_IF:
        if (opt_len != sizeof(net_if_peer_net_if_t)) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        if (!NET_IF_VIRT_IS_CONNECTED(virt)) {
            return ERR_SET_ERR(LUNE_ERR_NET_IF_NOT_CONNECTED);
        }

        ((net_if_peer_net_if_t *)opt_val)->id = virt->peer_virt->id;
        ((net_if_peer_net_if_t *)opt_val)->core_id = virt->peer_virt->core_id;

        break;
    case NET_IF_OPT_GET_CONN_TYPE:
        if (opt_len != sizeof(net_if_conn_type_en)) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        *(unsigned int *)opt_val = virt->conn_type;
        break;
    default:
        return ERR_SET_ERR(LUNE_ERR_NOT_SUPPORTED);
    }

    return 0;
}

static int net_if_virt_set_opt(net_if_virt_t *virt,
    net_if_opt_en opt,
    const unsigned char *opt_val,
    unsigned int opt_len __attribute__((unused)))
{
    net_if_virt_t *peer_virt;

    switch (opt) {
    case NET_IF_OPT_SET_MTU:
        virt->mtu = *(const unsigned short *)opt_val;
        break;
    case NET_IF_OPT_CONNECT_LOCAL:
    {
        net_if_t *peer_ifp;

        if (1 != lune_atomic32_inc_and_return(&virt->conn_cnt)) {
            lune_atomic32_dec(&virt->conn_cnt);
            return ERR_SET_ERR(LUNE_ERR_NET_IF_ALREADY_CONNECTED);
        }

        lune_assert(!NET_IF_VIRT_IS_CONNECTED(virt));

        if (NULL == (peer_ifp = net_if_get_net_if_by_id(*(const unsigned int *)opt_val))) {
            lune_atomic32_dec(&virt->conn_cnt);
            return ERR_SET_ERR(LUNE_ERR_NET_IF_NOT_FOUND);
        }

        if (LUNE_NET_IF_VIRT != NET_IF_GET_TYPE(peer_ifp)) {
            lune_atomic32_dec(&virt->conn_cnt);
            return ERR_SET_ERR(LUNE_ERR_NET_IF_UNEXPECTED_TYPE);
        }

        lune_assert(NULL != (peer_virt = NET_IF_GET_DATA(peer_ifp)));

        if (1 != lune_atomic32_inc_and_return(&peer_virt->conn_cnt)) {
            lune_atomic32_dec(&peer_virt->conn_cnt);
            lune_atomic32_dec(&virt->conn_cnt);
            return ERR_SET_ERR(LUNE_ERR_NET_IF_ALREADY_CONNECTED);
        }

        lune_assert(!(NET_IF_VIRT_IS_CONNECTED(peer_virt)));

        net_if_virt_connect_virt(virt, peer_virt, 1);
        break;
    }
    case NET_IF_OPT_DISCONNECT_LOCAL:
        if (NET_IF_IS_ACTIVE(virt->ifp)) {
            /* disconnect after disable */
            return ERR_SET_ERR(LUNE_ERR_NET_IF_ACTIVE);
        }

        if (!NET_IF_VIRT_IS_CONNECTED(virt)) {
            return ERR_SET_ERR(LUNE_ERR_NET_IF_NOT_CONNECTED);
        }

        if (NET_IF_CONN_TYPE_LOCAL != virt->conn_type) {
            return ERR_SET_ERR(LUNE_ERR_NET_IF_UNEXPECTED_CONN_TYPE);
        }

        peer_virt = virt->peer_virt;
        lune_assert(NET_IF_VIRT_IS_CONNECTED(peer_virt));
        lune_assert(NET_IF_CONN_TYPE_LOCAL == peer_virt->conn_type);

        if (NET_IF_IS_ACTIVE(peer_virt->ifp)) {
            /* disconnect after disable */
            return ERR_SET_ERR(LUNE_ERR_NET_IF_ACTIVE);
        }

        net_if_virt_disconnect_virt(virt);

        lune_atomic32_dec(&peer_virt->conn_cnt);
        lune_atomic32_dec(&virt->conn_cnt);
        break;
    case NET_IF_OPT_CONNECT_REMOTE:
    {
        net_if_virt_t v;
        const net_if_peer_net_if_t *peer = (const net_if_peer_net_if_t *)opt_val;

        if (1 != lune_atomic32_inc_and_return(&virt->conn_cnt)) {
            lune_atomic32_dec(&virt->conn_cnt);
            return ERR_SET_ERR(LUNE_ERR_NET_IF_ALREADY_CONNECTED);
        }

        lune_assert(!NET_IF_VIRT_IS_CONNECTED(virt));

        v.core_id = peer->core_id;
        v.id = peer->id;
        if (NULL == (peer_virt = htable_find_mt((void *)&v, s_net_if_virt_htable))) {
            lune_atomic32_dec(&virt->conn_cnt);
            return ERR_SET_ERR(LUNE_ERR_NET_IF_NOT_FOUND);
        }

        lune_assert(LUNE_NET_IF_VIRT == NET_IF_GET_TYPE(peer_virt->ifp));

        if (1 != lune_atomic32_inc_and_return(&peer_virt->conn_cnt)) {
            lune_atomic32_dec(&peer_virt->conn_cnt);
            htable_find_done_mt((void *)peer_virt, s_net_if_virt_htable);
            lune_atomic32_dec(&virt->conn_cnt);
            return ERR_SET_ERR(LUNE_ERR_NET_IF_ALREADY_CONNECTED);
        }

        lune_assert(!(NET_IF_VIRT_IS_CONNECTED(peer_virt)));

        net_if_virt_connect_virt(virt, peer_virt, 0);
        htable_find_done_mt((void *)peer_virt, s_net_if_virt_htable);
        break;
    }
    case NET_IF_OPT_DISCONNECT_REMOTE:
        if (NET_IF_IS_ACTIVE(virt->ifp)) {
            /* disconnect after disable */
            return ERR_SET_ERR(LUNE_ERR_NET_IF_ACTIVE);
        }

        if (!NET_IF_VIRT_IS_CONNECTED(virt)) {
            return ERR_SET_ERR(LUNE_ERR_NET_IF_NOT_CONNECTED);
        }

        if (NET_IF_CONN_TYPE_REMOTE_ACTIVE != virt->conn_type) {
            return ERR_SET_ERR(LUNE_ERR_NET_IF_UNEXPECTED_CONN_TYPE);
        }

        peer_virt = virt->peer_virt;
        lune_assert(NET_IF_VIRT_IS_CONNECTED(peer_virt));
        lune_assert(NET_IF_CONN_TYPE_REMOTE_PASSIVE == peer_virt->conn_type);

        if (NET_IF_IS_ACTIVE(peer_virt->ifp)) {
            /* disconnect after disable */
            return ERR_SET_ERR(LUNE_ERR_NET_IF_ACTIVE);
        }

        net_if_virt_disconnect_virt(virt);

        lune_atomic32_dec(&peer_virt->conn_cnt);
        lune_atomic32_dec(&virt->conn_cnt);
        break;
    case NET_IF_OPT_DISABLE_HW_CSUM:
        lune_log(LUNE_INFO, "checksum offload not supported on %s", virt->name);
        /* fall through */
    default:
        return ERR_SET_ERR(LUNE_ERR_NOT_SUPPORTED);
    }

    return 0;
}

net_if_drv_t g_net_if_drv_virt = {
    .type = LUNE_NET_IF_VIRT,
    .name = "virtual",
    .add_net_if = (net_if_add_net_if_func_t)net_if_virt_add_net_if,
    .del_net_if = (net_if_del_net_if_func_t)net_if_virt_del_net_if,
    .is_up = NULL,
    .set_up = NULL,
    .set_down = NULL,
    .send = (net_if_send_func_t)net_if_virt_send,
    .send_pkts = NULL,
    .recv = (net_if_recv_func_t)net_if_virt_recv,
    .recv_pkts = NULL,
    .recv_done = (net_if_recv_done_func_t)net_if_virt_recv_done,
    .recv_fwd_pkt = (net_if_recv_fwd_pkt_func_t)net_if_virt_recv_fwd_pkt,
    .recv_free_pkt = (net_if_recv_free_pkt_func_t)net_if_virt_recv_free_pkt,
    .get_opt = (net_if_get_opt_func_t)net_if_virt_get_opt,
    .set_opt = (net_if_set_opt_func_t)net_if_virt_set_opt,
};
