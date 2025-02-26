#
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2020-2024 Lune Reseau, Inc.
#

drv_sources = files('aggr.c',
    'init.c',
    'net_if.c',
    'net_if_chan.c',
    'net_if_std.c',
    'net_if_virt.c')

# build dpdk driver if enabled
if lune_conf.get('LUNE_DPDK') == 1
    subdir('dpdk')
endif

sources += drv_sources
