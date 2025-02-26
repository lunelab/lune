#
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2020-2024 Lune Reseau, Inc.
#

# check if OS is supported, only linux for now
supported_exec_envs = ['linux']
exec_env = host_machine.system()
if not supported_exec_envs.contains(exec_env)
    error('unsupported system type "@0@"'.format(exec_env))
endif

# extract all version information into the build configuration
pver = meson.project_version().split('.')
lune_conf.set_quoted('LUNE_VER_PREFIX', 'lune')
lune_conf.set('LUNE_VER_MAJOR', pver.get(0).to_int())
lune_conf.set('LUNE_VER_MINOR', pver.get(1).to_int())
lune_conf.set('LUNE_VER_REV', pver.get(2).to_int())

# enable extra warnings and disable any unwanted warnings
warning_flags = [
    '-Wcast-align',
    '-Wdeprecated',
    '-Wformat-security',
    '-Wmissing-declarations',
    '-Wno-strict-aliasing',
    '-Wpointer-arith',
    '-Wstrict-prototypes',
    '-Wundef',
    '-Wwrite-strings']

foreach arg: warning_flags
    if cc.has_argument(arg)
        add_project_arguments(arg, language: 'c')
    endif
endforeach

# specify -D_GNU_SOURCE unconditionally
add_project_arguments('-D_GNU_SOURCE', language: 'c')

# specify -DLUNE_BUILD for LUNE building process
add_project_arguments('-DLUNE_BUILD', language: 'c')

ext_dep = []

if get_option('enable_dpdk')
    lune_conf.set('LUNE_DPDK', 1)

    add_project_arguments('-DLUNE_BUILD_DPDK', language: 'c')
    add_project_arguments('-include', 'rte_config.h', language: 'c')
    add_project_arguments('-I/usr/local/include', language: 'c')
    add_project_link_arguments('-Wl,-rpath', '/usr/local/lib64', language: 'c')

    dl_dep = cc.find_library('dl', required: true)
    if not dl_dep.found()
        error('libdl not found, which is required by dpdk driver')
    endif
    add_project_link_arguments('-ldl', language: 'c')

    dpdk_dep = dependency('libdpdk', method: 'pkg-config')
    if not dpdk_dep.found()
        error('dpdk not found, which is required by dpdk driver')
    endif
    ext_dep += dpdk_dep
else
    lune_conf.set('LUNE_DPDK', 0)
endif

if get_option('enable_ssl')
    lune_conf.set('LUNE_SSL', 1)

    add_project_arguments('-DLUNE_BUILD_SSL', language: 'c')

    openssl_dep = dependency('openssl', version: '>= 1.1.1', method: 'pkg-config')
    if not openssl_dep.found()
        error('openssl not found, which is required by lune ssl')
    endif
    ext_dep += openssl_dep

    openssl_rpath = run_command('sh', '-c', 'pkgconf --libs-only-L openssl | sed "s/^-L//"').stdout().strip()
    install_rpaths += openssl_rpath
else
    lune_conf.set('LUNE_SSL', 0)
endif

if get_option('enable_mem_dbg_print')
    lune_conf.set('LUNE_MEM_DBG_PRINT', 1)
else
    lune_conf.set('LUNE_MEM_DBG_PRINT', 0)
endif

if get_option('enable_mem_dbg_oob_l1')
    add_project_arguments('-DLUNE_BUILD_MEM_DBG_OOB_L1', language: 'c')
endif

if get_option('enable_mem_dbg_oob_l2')
    add_project_arguments('-DLUNE_BUILD_MEM_DBG_OOB_L2', language: 'c')
endif
