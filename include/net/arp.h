/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2024 Lune Reseau, Inc.
 */

#ifndef __ARP_H__
#define __ARP_H__

#include "lune/ipv4.h"
#include "lune/mac.h"
#include "lune/net.h"

#include "net/ip.h"
#include "net/mac.h"
#include "net/pbuf.h"

int ipv4_route(mac_t *macp, lune_mac_addr_t dst_mac,
    ip_t *ipv4p, lune_ipv4_addr_t dst_addr, pbuf_t *pbuf);

int arp_input(mac_t *macp, pbuf_t *pbuf);

int arp_send_req(ip_t *ipv4p, lune_ipv4_addr_t dst_addr);

#endif