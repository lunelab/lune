#
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2020-2024 Lune Reseau, Inc.
#

net_sources = files('arp.c',
    'icmp.c',
    'igmp.c',
    'init.c',
    'ip.c',
    'ipv4.c',
    'ipv6.c',
    'mac.c',
    'nb.c',
    'pbuf.c',
    'socket.c',
    'tcp.c',
    'udp.c')

# build openssl adapter if enabled
if lune_conf.get('LUNE_SSL') == 1
    net_sources += files('ssl.c',
        'ossl.c')
endif

sources += net_sources
