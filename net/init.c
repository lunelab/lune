/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2024 Lune Reseau, Inc.
 */

#include "drv/net_if.h"
#include "net/icmp.h"
#include "net/init.h"
#include "net/ip.h"
#include "net/mac.h"
#include "net/nb.h"
#include "net/pbuf.h"
#include "net/socket.h"
#ifdef LUNE_BUILD_SSL
#include "net/ssl.h"
#endif
#include "net/tcp.h"
#include "net/udp.h"

int net_aggr_local_init(void)
{
    int err;

    if (0 != (err = net_if_local_init())) {
        goto ERR_1;
    }

    if (0 != (err = socket_local_init())) {
        goto ERR_2;
    }

    return 0;

ERR_2:
    net_if_local_fini();

ERR_1:
    return ERR_GET_LAST_ERR();
}

void net_aggr_local_fini(void)
{
    socket_local_fini();
    net_if_local_fini();
}

int net_proc_local_init(void)
{
    int err;

    if (0 != (err = net_if_local_init())) {
        goto ERR_1;
    }

    if (0 != (err = mac_local_init())) {
        goto ERR_2;
    }

    if (0 != (err = nb_local_init())) {
        goto ERR_3;
    }

    if (0 != (err = ip_local_init())) {
        goto ERR_4;
    }

    if (0 != (err = tcp_local_init())) {
        goto ERR_5;
    }

    if (0 != (err = udp_local_init())) {
        goto ERR_6;
    }

    if (0 != (err = icmp_local_init())) {
        goto ERR_7;
    }

    if (0 != (err = igmp_local_init())) {
        goto ERR_8;
    }

    if (0 != (err = socket_local_init())) {
        goto ERR_9;
    }

    if (0 != (err = pbuf_local_init())) {
        goto ERR_10;
    }

#ifdef LUNE_BUILD_SSL
    if (0 != (err = ssl_local_init())) {
        goto ERR_11;
    }
#endif

    return 0;

#ifdef LUNE_BUILD_SSL
ERR_11:
    pbuf_local_fini();
#endif

ERR_10:
    socket_local_fini();

ERR_9:
    igmp_local_fini();

ERR_8:
    icmp_local_fini();

ERR_7:
    udp_local_fini();

ERR_6:
    tcp_local_fini();

ERR_5:
    ip_local_fini();

ERR_4:
    nb_local_fini();

ERR_3:
    mac_local_fini();

ERR_2:
    net_if_local_fini();

ERR_1:
    return err;
}

void net_proc_local_fini(void)
{
#ifdef LUNE_BUILD_SSL
    ssl_local_fini();
#endif
    pbuf_local_fini();
    socket_local_fini();
    igmp_local_fini();
    icmp_local_fini();
    udp_local_fini();
    tcp_local_fini();
    ip_local_fini();
    nb_local_fini();
    mac_local_fini();
    net_if_local_fini();
}

int net_init(void)
{
#ifdef LUNE_BUILD_SSL
    return ssl_init();
#else
    return 0;
#endif
}

void net_fini(void)
{
#ifdef LUNE_BUILD_SSL
    ssl_fini();
#endif
}
