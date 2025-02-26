LUNE-TTP: A tool for TCP/SSL traffic generation over ethernet interface
=============================================================

Summary
-------
The **LUNE-based Test TCP Performance** (**LUNE-TTP**) program is a built-in application on top of LUNE library. As an how-to example, it shows generation and reception of TCP/SSL traffic over a pair of ethernet interfaces. You can test scenarios such as CPS (connections per second), SPS (sessions per second), concurrent connections and data rate through different configurations.

Configuration
-------------
A template of configuration, in YAML format, has been included in the repo (ttp_example.yml).

The configuration is composed of 3 sections.

### `cpu` ###

In this section, cpu resources are configured with following parameters:
- `nrt`: non-runtime core on which all LUNE non-runtime tasks run. there should be one and only one non-runtime core.
- `rt_client_start`: starting core id of runtime core(s) on which all client runtime tasks run.
- `rt_client_na_num`: number of runtime core(s) on which NA(s) for client interface are deployed. minimum zero. core id starts with `rt_client_start` and increments by 1 till `rt_client_na_num`. NA represents Network Aggregator. see [LUNE Core Type](#lune-core-type) for further details.
- `rt_client_np_num`: number of runtime core(s) on which NP(s) for client interface are deployed. minimum one. core id starts with `rt_client_start` + `rt_client_na_num`, and increments by 1 till `rt_client_np_num`. NP represents Network Processor. see [LUNE Core Type](#lune-core-type) for further details.
- `rt_client_cp_num`: number of runtime core(s) on which CP(s) for client interface are deployed. minimum zero. core id starts with `rt_client_start` + `rt_client_na_num` + `rt_client_np_num`, and increments by 1 till `rt_client_cp_num`. CP represents Co-Processor. see [LUNE Core Type](#lune-core-type) for further details.
- `rt_server_start`: starting core id of runtime core(s) on which all server runtime tasks run. similar to `rt_client_start`.
- `rt_server_na_num`: number of runtime core(s) on which NA(s) for server interface are deployed. similar to `rt_client_na_num`.
- `rt_server_np_num`: number of runtime core(s) on which NP(s) for server interface are deployed. similar to `rt_client_np_num`.
- `rt_server_cp_num`: number of runtime core(s) on which CP(s) for server interface are deployed. similar to `rt_client_cp_num`.

Just note that:
- three cores are the minimum requirement of cpu resources to run `lune-ttp`. i.e., one for nrt, one for client NP, one for server NP.
- one core must be assigned to one type only. e.g., one core can only be assigned to either nrt, or client/server NA, NP or CP.
- `rt_client_na_num` or `rt_server_na_num` may configure more than one core only if client or server interface is set to ***dpdk_queue*** type.
- when `rt_client_na_num` or `rt_server_na_num` is set to zero, `rt_client_np_num` or `rt_server_np_num`, may configure more than one core only if client or server interface is set to ***dpdk_queue*** type.

### `interface` ###

In this section, a pair of interfaces are configured with following parameters:
- `client`: generates traffic, and if configured, receives traffic sent back by server.
  - `name`: client interface name. e.g., "eth0" for ***standard*** type, "0000:06:00.0" for ***dpdk*** type.
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
- `rate`: connections/sessions per second.
- `payload_len`: total payload length in a tcp/ssl packet.
- `pkt_cnt`: number of tcp/ssl packets sent per connection.
- `max_cc`: maximum concurrent connections, no more connection establishment is attempted once `max_cc` is reached.
- `pkt_intvl`: time interval between packets (in millisecond).
- `ip`: ***ipv4*** or ***ipv6***.
- `ssl`: ***none***, ***tls1.2*** or ***tls1.3***.
  - ***none***: tcp only.
  - ***tls1.2***: tlsv1.2 on top of tcp.
  - ***tls1.3***: tlsv1.3 on top of tcp.

LUNE Core Type
--------------

There are three core types in LUNE so far:
### NA ###

Network Aggregator. An NA aggregates outgoing traffic from NPs and distributes incoming traffic to NPs through interface added on it. interface added on NA is called aggregated interface internally. it's connected to interfaces added on NPs, which are called channel interfaces internally. 

### NP ###

Network Processor. An NP generates outgoing traffic and processes incoming traffic on interface(s) added on it. for channel interface, all traffic will go through aggregated interface on NA. for non-channel interface, all traffic will go through the interface directly.

### CP ###

Co-Processor. A CP processes asynchronous events offloaded from NP. it's mainly used to offload SSL establishment and data encryption/decryption for now. it is suggested to set to zero if SSL is not involved.

Performance
-----------
The optimal performance **LUNE-TTP** can achieve is affected by several factors in hardware and software.

### Hardware ###

- CPU
  - number of physical cores available determines parallel processing capability. more physical cores available for the run, more resources for NA, NP and CP allocation, hence higher parallel processing, which ends up with higher performance in most scenarios.
  - frequency determines packet processing speed. workload like CPS test will certainly benefit from higher CPU frequency.
  - NUMA coherency guarantees I/O efficiency for multi-CPU hardware. one should make sure cores allocated for NA/NP/CP of client/server interface are on the same CPU as that the interface is physically connected to, so that cross-CPU data access, which increases latency and reduces throughput, is avoided.
- memory
  - memory capacity determines concurrency capability in general. in LUNE, higher memory allows more active MACs, IPs, TCP/SSL connections.
  - memory speed impacts data access directly. performance of large packet read/write will benefit significantly from high memory I/O rate.

### Software ###

- DPDK
  - DPDK, as a high-performance, user-space networking framework, is designed to enable fast packet processing on CPUs. it's well integrated in LUNE and provided as interface type ***dpdk*** and ***dpdk_queue***. install, enable DPDK in LUNE build and leverage it to reach LUNE's best performance.
- Configuration
  - core allocation for NA/NP/CP. by adjusting number of cores among NA/NP/CP and verifying it in runtime, optimal performance, under same other conditions, can be uncovered.

Hereafter a summary of some performance metrics obtained from test conducted in our lab:
- TCP CPS
  - 130,000 established connections per second per physical core. it means 130K cps is the average performance on one core. with multiple cores applied, performance is expected to be multiplied. in other words, performance grows near linearly over number of physical cores. e.g., if 10 physical cores are configured, TCP CPS may potentially reach 1.3M cps with proper configuration. the per-physical-core data can be used to roughly estimate performance with given number of cores. similar applies to other per-physical-core performance metrics below.
  - A TCP connection above contains a 3-handshake establishment and a reset closure.
- SSL SPS
  - 3,000 established sessions per second per physical core.
  - A SSL session above contains a TCP connection establishment, a SSL session establishment with tlsv1.2 and a TCP reset closure.
- TCP data rate
  - 3.4Gbps per physical core.
  - Data rate above is reached with `payload_len` set to 1460.

Notes:
- the test was carried out in our lab, with a back-to-back connection of two 100Gbps ethernet interfaces. hardware for the test:
  - processor type: Intel Xeon Gen-2
  - processor frequency: 2.2GHz
  - memory type: DDR4
  - memory speed: 2400MHz
  - ethernet interface type: Mellanox ConnectX-5 100Gbps
- the result shows the best performance only on hardware given above. performance may vary on different hardware platform (better or worse). Run test on your hardware for more accurate result.
- as mentioned, performance data provided above is "per physical core" instead of "per logical core". hyper-thread was disabled in our test to make sure every core visible in OS is a physical core.
