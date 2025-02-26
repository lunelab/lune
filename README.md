LUNE: A library for network traffic generation and processing
=============================================================

Summary
-------

The **Lightweight Universal Network Engine** (**LUNE**) is an open soure software project managed by Lune Reseau, Inc.. Development for LUNE takes place mainly on Ubuntu Linux and CentOS Linux.

LUNE provides a library that implements major L2-L5 protocols running in user space and achieving high performance of network traffic generation and processing.

It supports:
- simulation of massive MAC addresses
- simulation of massive IP adresses
- simulation of massive TCP connections
- simulation of massive SSL sessions
- L2-L5 protocols
  - L2: MAC/VLAN/ARP
  - L3: IPv4/IPv6/ICMP/IGMP
  - L4: TCP/UDP
  - L5: SSL (OpenSSL required)
- high L4-L5 performance (hardware dependent, DPDK required)
  - L4 connection rate: millions of TCP connections establishment per second
  - L4 concurrent connections: tens of millions of concurrent TCP connections
  - L5 session rate: tens of thousands of SSL sessions establishment per second
  - L5 concurrent sessions: tens of millions of concurrent SSL sessions
- simulation of one-arm (only client or server) and two-arm (both client and server)
- traffic mix (different protocols, different layers)
- scalability

License
-------

LUNE and its built-in APPs are licensed under **BSD-3-Clause license**.

Build
-----

LUNE build configuration can be modified in `meson_option.txt`. The default configuration makes minimal build with least dependencies, i.e., DPDK and SSL disabled.

### Prerequisites ###

    # install LUNE dependencies
    sudo apt install meson pkgconf
    # install LUNE built-in APPs dependencies
    sudo apt install libyaml-dev

### Build ###

    # download LUNE from github
    git clone https://github.com/lunelab/lune.git
    cd lune
    # create build configuration by meson
    meson setup build
    # build by ninja
    cd build
    ninja

### Test ###

    # test with lune-tip, one of the built-in APPs
    cd app
    ./lune-tip -f ../../app/tip/tip_example.yml
    # when it completes, check logs to see if it's a successful run
    grep TIP *.log

expected result:

    ...
    tip_np_2.log:D 2025-01-01 00:02:17 [TIP] 27 sec: Tx_pkt 0.00M Tx_pps 0.00M Tx_byte 0.00M Tx_bps 0.00M Rx_pkt 0.22M Rx_pps 0.01M Rx_byte 22.46M Rx_bps 8.05M
    tip_np_2.log:D 2025-01-01 00:02:18 [TIP] 28 sec: Tx_pkt 0.00M Tx_pps 0.00M Tx_byte 0.00M Tx_bps 0.00M Rx_pkt 0.23M Rx_pps 0.01M Rx_byte 23.46M Rx_bps 7.97M
    tip_np_2.log:D 2025-01-01 00:02:19 [TIP] 29 sec: Tx_pkt 0.00M Tx_pps 0.00M Tx_byte 0.00M Tx_bps 0.00M Rx_pkt 0.24M Rx_pps 0.01M Rx_byte 24.46M Rx_bps 8.04M
    tip_np_2.log:D 2025-01-01 00:02:20 [TIP] 30 sec: Tx_pkt 0.00M Tx_pps 0.00M Tx_byte 0.00M Tx_bps 0.00M Rx_pkt 0.25M Rx_pps 0.01M Rx_byte 25.47M Rx_bps 8.03M
    tip_np_2.log:D 2025-01-01 00:02:21 [TIP] 31 sec: Tx_pkt 0.00M Tx_pps 0.00M Tx_byte 0.00M Tx_bps 0.00M Rx_pkt 0.26M Rx_pps 0.01M Rx_byte 26.47M Rx_bps 8.00M
    ...

(Note: Make sure there are at least 3 cores in order to run the test)

Build with SSL
--------------

Do as follows before build:

### Prerequisite ###

    # download, configure, compile, and install OpenSSL 1.1.1 (OpenSSL 3 not supported yet)
    wget https://www.openssl.org/source/openssl-1.1.1.tar.gz
    tar -xzf openssl-1.1.1.tar.gz
    cd openssl-1.1.1
    ./config --prefix=/usr/local/openssl-1.1.1 --openssldir=/usr/local/openssl-1.1.1
    make
    sudo make install
    # make OpenSSL 1.1.1 libraries searchable for current login user
    echo 'export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/openssl-1.1.1/lib' >> ~/.bashrc
    echo 'export PKG_CONFIG_PATH=$PKG_CONFIG_PATH:/usr/local/openssl-1.1.1/lib/pkgconfig' >> ~/.bashrc
    source ~/.bashrc
    # make OpenSSL 1.1.1 header files searchable
    sudo ln -s /usr/local/openssl-1.1.1/include/openssl /usr/local/include/openssl

### Configuration for Build ###

Enable SSL in `meson_option.txt` before build:

    option('enable_ssl', type: 'boolean', value: true,
        description: 'build ssl stack with support of openssl')

Go on to [Build](#build).

Build with DPDK
--------------

Do as follows before build:

### Prerequisite ###

Download, build, install DPDK and prepare DPDK runtime environment. Please see [DPDK official site](https://dpdk.org) for further information.

### Configuration for Build ###

Enable DPDK in `meson_option.txt` before build:

    option('enable_dpdk', type: 'boolean', value: true,
        description: 'build dpdk driver')

Go on to [Build](#build).

Built-in APPs
------------

There are two built-in APPs included in the project, **LUNE-TIP** and **LUNE-TTP**, showing examples of how to use LUNE APIs to generate L2 and L4 traffic respectively.

For further information, see [LUNE-TIP README](./app/tip/README.md) and [LUNE-TTP README](./app/ttp/README.md).

Bug Report
----------

Report bugs and issues to the development mailing list: dev@lunelab.net.
