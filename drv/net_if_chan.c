/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2024 Lune Reseau, Inc.
 */

#include "lune/log.h"
#include "lune/mem.h"
#include "lune/net_if.h"
#include "lune/os/linux.h"
#include "lune/time.h"
#include "lune/timer.h"

#include "drv/aggr.h"
#include "drv/net_if.h"
#include "drv/net_if_chan.h"
#include "net/socket.h"

typedef struct _net_if_chan {
    char name[LUNE_MAX_SHORT_NAME_BUF_LEN];
    void *acp;
    net_if_t *ifp;
    lune_net_if_stats_t stats;
    unsigned short mtu;
    unsigned short csum_offloads;
#define NET_IF_CHAN_FLAG_UP                    0x00000001
#define NET_IF_CHAN_IS_UP(chan)                \
    (((net_if_chan_t *)(chan))->flags & NET_IF_CHAN_FLAG_UP)
#define NET_IF_CHAN_SET_UP(chan)               \
    do { ((net_if_chan_t *)(chan))->flags =    \
        (((net_if_chan_t *)(chan))->flags | (NET_IF_CHAN_FLAG_UP)); } while (0)
#define NET_IF_CHAN_SET_DOWN(chan)             \
    do { ((net_if_chan_t *)(chan))->flags =    \
        (((net_if_chan_t *)(chan))->flags & (~NET_IF_CHAN_FLAG_UP)); } while (0)
    unsigned int flags;
} net_if_chan_t;

net_if_t *net_if_chan_get_aggr_ifp(net_if_t *ifp)
{
    lune_assert(LUNE_NET_IF_CHAN == ifp->type);
    return aggr_chan_get_aggr_ifp(((net_if_chan_t *)ifp->net_if_data)->acp);
}

static int net_if_chan_init_chan(net_if_chan_t *chan, const char *name, net_if_t *ifp)
{
    int err;
    net_if_t *ai_ifp;

    if (NULL == (chan->acp = aggr_add_chan(name, ifp))) {
        err = ERR_GET_LAST_ERR();
        goto ERR_1;
    }

    strcpy(chan->name, name);
    chan->ifp = ifp;
    memset(&chan->stats, 0x00, sizeof(lune_net_if_stats_t));
    /* ifp->mtu has been updated within aggr_add_chan() */
    chan->mtu = ifp->mtu;
    chan->flags = 0;

    lune_assert(NULL != (ai_ifp = aggr_chan_get_aggr_ifp(chan->acp)));
    if (0 != (err = ai_ifp->drv->get_opt(ai_ifp->net_if_data,
        NET_IF_OPT_GET_HW_CSUM, (unsigned char *)&chan->csum_offloads, sizeof(chan->csum_offloads)))) {
        goto ERR_2;
    }

    return 0;

ERR_2:
    lune_assert(!aggr_del_chan(chan->acp));

ERR_1:
    return err;
}

static int net_if_chan_add_net_if(net_if_t *ifp,
    const char *name, const void *conf_val, unsigned int conf_len, void **pdata)
{
    net_if_chan_t *chan;
    int err;

    if (conf_val != NULL || conf_len != 0) {
        err = ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        goto ERR_1;
    }

    if (NULL == (chan = lune_malloc(sizeof(net_if_chan_t)))) {
        err = ERR_GET_LAST_ERR();
        goto ERR_1;
    }

    if (0 != (err = net_if_chan_init_chan(chan, name, ifp))) {
        goto ERR_2;
    }

    *pdata = chan;

    return 0;

ERR_2:
    lune_free(chan);

ERR_1:
    return err;
}

static int net_if_chan_del_net_if(net_if_chan_t *chan)
{
    int err;

    lune_assert(NULL != chan->acp);

    if (0 != (err = aggr_del_chan(chan->acp))) {
        return err;
    }

    lune_free(chan);

    return 0;
}

static int net_if_chan_is_up(net_if_chan_t *chan)
{
    return NET_IF_CHAN_IS_UP(chan);
}

static int net_if_chan_set_up(net_if_chan_t *chan)
{
    net_if_t *ai_ifp;

    lune_assert(NULL != (ai_ifp = aggr_chan_get_aggr_ifp(chan->acp)));
    if (!NET_IF_IS_ACTIVE(ai_ifp)) {
        /* aggregated interface should be enabled first */
        return ERR_SET_ERR(LUNE_ERR_NET_IF_AGGR_NOT_ENABLED);
    }

    aggr_enable_chan(chan->acp);
    NET_IF_CHAN_SET_UP(chan);
    return 0;
}

static int net_if_chan_set_down(net_if_chan_t *chan)
{
    NET_IF_CHAN_SET_DOWN(chan);
    aggr_disable_chan(chan->acp);
    return 0;
}

static int net_if_chan_send(net_if_chan_t *chan, const unsigned char *buf, unsigned int len)
{
    int err;

    if (0 != (err = aggr_chan_send(chan->acp, buf, len, NET_IF_GET_CURR_TX_PBUF()))) {
        return err;
    }

    chan->stats.byte_out += len;
    chan->stats.pkt_out++;

    return 0;
}

static int net_if_chan_recv(net_if_chan_t *chan, const unsigned char **pbuf, unsigned int *plen)
{
    int err;

    if (0 != (err = aggr_chan_recv(chan->acp, pbuf, plen))) {
        return err;
    }

    chan->stats.byte_in += *plen;
    chan->stats.pkt_in++;

    return 0;
}

static void net_if_chan_recv_done(net_if_chan_t *chan)
{
    aggr_chan_recv_done(chan->acp);
}

static int net_if_chan_get_opt(net_if_chan_t *chan,
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

        *(unsigned short *)opt_val = chan->csum_offloads;
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

        *(unsigned short *)opt_val = chan->mtu;
        break;
    case NET_IF_OPT_GET_STATS:
        if (opt_len != sizeof(lune_net_if_stats_t)) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        memcpy(opt_val, &chan->stats, sizeof(lune_net_if_stats_t));
        break;
    case NET_IF_OPT_GET_CHAN_ID:
        if (opt_len != sizeof(unsigned int)) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }
        *(unsigned int *)opt_val = aggr_chan_get_id(chan->acp);
        break;
    default:
        return ERR_SET_ERR(LUNE_ERR_NOT_SUPPORTED);
    }

    return 0;
}

static int net_if_chan_set_opt(net_if_chan_t *chan,
    net_if_opt_en opt,
    const unsigned char *opt_val,
    unsigned int opt_len __attribute__((unused)))
{
    lune_assert(NULL != opt_val);

    switch (opt) {
    case NET_IF_OPT_DISABLE_HW_CSUM:
        lune_log(LUNE_INFO, "checksum offload not supported on %s", chan->name);
        /* fall through */
    default:
        return ERR_SET_ERR(LUNE_ERR_NOT_SUPPORTED);
    }

    return 0;
}

net_if_drv_t g_net_if_drv_chan = {
    .type = LUNE_NET_IF_CHAN,
    .name = "channel",
    .add_net_if = (net_if_add_net_if_func_t)net_if_chan_add_net_if,
    .del_net_if = (net_if_del_net_if_func_t)net_if_chan_del_net_if,
    .is_up = (net_if_is_up_func_t)net_if_chan_is_up,
    .set_up = (net_if_set_up_func_t)net_if_chan_set_up,
    .set_down = (net_if_set_down_func_t)net_if_chan_set_down,
    .send = (net_if_send_func_t)net_if_chan_send,
    .send_pkts = NULL,
    .recv = (net_if_recv_func_t)net_if_chan_recv,
    .recv_pkts = NULL,
    .recv_done = (net_if_recv_done_func_t)net_if_chan_recv_done,
    .recv_fwd_pkt = NULL,
    .recv_free_pkt = NULL,
    .get_opt = (net_if_get_opt_func_t)net_if_chan_get_opt,
    .set_opt = (net_if_set_opt_func_t)net_if_chan_set_opt,
};
