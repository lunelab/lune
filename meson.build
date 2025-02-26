#
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2020-2024 Lune Reseau, Inc.
#

project('lune', 'C',
    # get version number from file.
    version: run_command(find_program('cat'),
        files('VERSION')).stdout().strip(),
    license: 'BSD',
    default_options: ['buildtype=debugoptimized', 'default_library=static'],
    meson_version: '>= 0.60.0'
)

# set up some global vars for compiler, configuration, etc.
cc = meson.get_compiler('c')

machine = 'native'
machine_args = []
machine_args += '-march=' + machine

cflags = machine_args
cflags += ['-Wcast-qual',
    '-Wsign-compare',
    '-Wunused-parameter']
if get_option('buildtype') == 'debug'
    cflags += ['-DLUNE_DEBUG']
endif

install_rpaths = []

# generate build configuration
lune_conf = configuration_data()

subdir('conf')

build_conf_file = 'build_conf.h'
configure_file(output: build_conf_file,
    configuration: lune_conf)

install_headers(join_paths(meson.current_build_dir(), build_conf_file),
    subdir: 'lune',
    install_mode: 'rw-r--r--')

# build libraries
sources = []
subdir('drv')
subdir('err')
subdir('include')
subdir('init')
subdir('kernel')
subdir('lib')
subdir('log')
subdir('main')
subdir('mem')
subdir('net')
subdir('nrt')
subdir('res')
subdir('rt')
subdir('utils')

lune_name = meson.project_name().to_lower()
lune_build_incs = include_directories('include')

lune_install_rpath = ':'.join(install_rpaths)

lune_libs = both_libraries(lune_name,
    sources: sources,
    install: true,
    install_rpath: lune_install_rpath,
    c_args: cflags,
    dependencies: ext_dep,
    include_directories: lune_build_incs)
lune_static_lib = lune_libs.get_static_lib()
lune_lib = lune_libs.get_shared_lib()

# build built-in applications
subdir('app')

# generate pkg-config info
pkg = import('pkgconfig')
pkg.generate(name: meson.project_name(),
    filebase: 'lib' + lune_name,
    version: meson.project_version(),
    libraries: lune_libs,
    description: '''Lightweight Universal Network Engine (LUNE).''',
    subdirs: ['.']
)
