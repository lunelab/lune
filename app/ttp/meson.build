#
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2020-2024 Lune Reseau, Inc.
#
# Lune Test Tcp Perf tool
#

ttp_sources = files('main.c', 'ttp.c')

if lune_conf.get('LUNE_SSL') == 1
    ttp_sources += files('ssl.c')
endif

yaml_dep = cc.find_library('yaml', required: false)
if not yaml_dep.found()
    message('libyaml not found, which is required by lune-ttp')
    message('skip building lune-ttp')
    subdir_done()
endif

sources += ttp_sources
dep_libs += yaml_dep
