#
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2020-2024 Lune Reseau, Inc.
#

utils_sources = files('cap.c')

sources += utils_sources

if lune_conf.get('LUNE_DPDK') == 1
    utils_dpdk_sources = files('net_if_dpdk_cap.c')
    sources += utils_dpdk_sources
endif