#
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2020-2024 Lune Reseau, Inc.
#

apps = ['tip', 'ttp']

app_incs = [lune_build_incs]
app_incs += include_directories('./include', '..')

foreach app:apps
    name = app
    # default app name, may be overwritten while subdirring
    app_name = 'lune-' + name
    dep_libs = []
    link_static_libs = []
    link_libs = []
    sources = []

    if lune_conf.get('LUNE_DPDK') == 1
        dep_libs += dpdk_drv_deps
    endif

    if get_option('default_library') == 'static'
        link_static_libs += lune_static_lib
    else
        link_libs += lune_lib
    endif

    subdir(name)
    if sources.length() != 0
        executable(app_name,
            sources,
            include_directories: app_incs,
            link_with: link_libs,
            link_whole: link_static_libs,
            dependencies: dep_libs)
    endif
endforeach
