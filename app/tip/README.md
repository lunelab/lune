LUNE-TIP: A tool for L2 traffic generation over ethernet interface
=============================================================

Summary
-------
The **LUNE-based Test Interface Performance** (**LUNE-TIP**) program is a built-in application on top of LUNE library. As an how-to example, it shows generation and reception of L2 traffic over a pair of ethernet interfaces. You can test L2 throughput or pps (packets per second) through different configurations.

Configuration
-------------
A template of configuration, in YAML format, has been included in the repo (tip_example.yml).

The configuration is composed of 4 sections.

### `cpu` ###

In this section, cpu resources are configured with following parameters:
- `nrt`: non-runtime core on which all LUNE non-runtime tasks run. there should be one and only one non-runtime core.
- `rt_client_start` and `rt_client_core_num`: runtime core(s) on which all client runtime tasks run. minimum one. `rt_client_start` means starting core id, and it increments by 1 till `rt_client_core_num` is reached. e.g., with `rt_client_start` set to 2 and `rt_client_core_num` set to 3, core 2, 3 and 4 are used to run traffic on client interface.
- `rt_server_start` and `rt_server_core_num`: runtime core(s) on which all server runtime tasks run. minimum one. similar to `rt_client_start` and `rt_client_core_num`.

Just note that:
- three cores are the minimum requirement of cpu resources to run `lune-tip`. i.e., one for nrt, one for client and one for server.
- one core must be assigned to one type only. e.g., one core can only be assigned to either nrt, or client, or server.
- the only case where `rt_client_core_num` and `rt_server_core_num` may configure more than one core is with ***dpdk_queue*** interface type.

### `interface` ###

In this section, a pair of interfaces are configured with following parameters:
- `client`: generates traffic, and if configured, receives traffic sent back by server.
  - `name`: client interface name. e.g., "eth0" for ***standard*** type, "0000:06:00.0" for ***dpdk*** or ***dpdk_queue*** type.
  - `type`: ***virtual***, ***standard***, ***dpdk*** or ***dpdk_queue***.
    - ***virtual***: as literal meaning, it's not a real interface and will not be detected by OS. it's managed and recognized within LUNE only. virtual interface can only be paired with virtual interface. any name can be given to virtual interface as long as it's not used by other virtual interfaces.
    - ***standard***: interface recognized by OS and typically named with "eth0", "eth1", and so on.
    - ***dpdk***: interface recognized by DPDK and typically named with "0000:06:00.0", "0000:06:00.1", and so on. DPDK and DPDK-enabled LUNE required.
    - ***dpdk_queue***: the only difference with ***dpdk*** is that ***dpdk_queue*** leverages DPDK multiple RX TX queues to distribute/aggregate traffic among queues and attain better performance.
  - `capture`: enable or disable packet capture on the interface. once enabled, a .pcap file (up to 100MB) will be created and capture all packets on the interface.
- `server`: receives traffic, and if configured, sends traffic back to client.
  - `name`: server interface name.
  - `type`: the same as `type` in `client`.
  - `capture`: the same as `capture` in `client`.

### `load` ###

In this section, traffic pattern is configured with following parameters:

- `time`: total duration of the run.
- `pps`: number of packets sent per second.
- `pkt_size`: total size of packet on the wire.
- `resp`: enable or disable sending response on server side. once enabled, server sends every packet back right after receiving it.

### `system` ###

- `hz`: LUNE core scheduling cycle. change not recommended.
