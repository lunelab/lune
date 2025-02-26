#
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2020-2024 Lune Reseau, Inc.
#

lune_headers = files('lune/arp.h',
    'lune/assert.h',
    'lune/atomic.h',
    'lune/comm.h',
    'lune/common.h',
    'lune/conf.h',
    'lune/conv.h',
    'lune/core.h',
    'lune/cpu.h',
    'lune/csum.h',
    'lune/err.h',
    'lune/icmp.h',
    'lune/id.h',
    'lune/idtable.h',
    'lune/igmp.h',
    'lune/init.h',
    'lune/ip.h',
    'lune/ipv4.h',
    'lune/ipv6.h',
    'lune/list.h',
    'lune/log.h',
    'lune/lune.h',
    'lune/mac.h',
    'lune/mem.h',
    'lune/nb.h',
    'lune/net.h',
    'lune/net_if.h',
    'lune/sched.h',
    'lune/socket.h',
    'lune/ssl.h',
    'lune/tcp.h',
    'lune/thread.h',
    'lune/time.h',
    'lune/timer.h',
    'lune/tiny_idtable.h',
    'lune/udp.h')

lune_os_headers = files('lune/os/linux.h')

# configure headers for installation
install_headers(lune_headers,
    subdir: 'lune',
    install_mode: 'rw-r--r--')

install_headers(lune_os_headers,
    subdir: 'lune/os',
    install_mode: 'rw-r--r--')