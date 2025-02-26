#
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2020-2024 Lune Reseau, Inc.
#
# Lune Test Interface Perf tool
#

tip_sources = files('main.c', 'tip.c')

yaml_dep = cc.find_library('yaml', required: false)
if not yaml_dep.found()
    message('libyaml not found, which is required by lune-tip')
    message('skip building lune-tip')
    subdir_done()
endif

sources += tip_sources
dep_libs += yaml_dep
