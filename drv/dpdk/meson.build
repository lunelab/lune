#
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2020-2024 Lune Reseau, Inc.
#
# 1. make sure platform-specific prerequisites (firmware, etc.) are met, may (or may not) need to modify rte_config.h
#    and other parameters to build necessary platform-specific driver, depending on DPDK release
# 2. build and install dpdk
# 3. echo 1024 > /sys/devices/system/node/nodex/hugepages/hugepages-2048kB/nr_hugepages only if nr_hugepages == 0
# 4. build project with enable_dpdk
# 5. dpdk-devbind.py --status
# 6. modprobe <driver_name> e.g. uio_pci_generic
# 7. dpdk-devbind.py --bind=<module_name> <interface_name>
#

drv_sources += files('net_if_dpdk.c',
    'net_if_dpdk_chan.c',
    'net_if_dpdk_queue.c',
    'net_if_dpdk_queue_chan.c')

dpdk_drv_deps = []

if get_option('default_library') == 'static'
    dpdk_ldflags = run_command('sh', '-c', 'pkgconf --static --libs libdpdk').stdout()
else
    dpdk_ldflags = run_command('sh', '-c', 'pkgconf --libs libdpdk').stdout()
endif
dpdk_drv_deps += declare_dependency(link_args: dpdk_ldflags.split())

dpdk_rpath = run_command('sh', '-c', 'pkgconf --libs-only-L libdpdk | sed "s/^-L//"').stdout().strip()
install_rpaths += dpdk_rpath
