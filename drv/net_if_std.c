/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2024 Lune Reseau, Inc.
 */

#include "lune/err.h"
#include "lune/id.h"
#include "lune/ipv4.h"
#include "lune/log.h"
#include "lune/mac.h"
#include "lune/mem.h"
#include "lune/net_if.h"
#include "lune/os/linux.h"
#include "lune/timer.h"

#include "drv/net_if_std.h"
#include "kernel/sched.h"
#include "net/socket.h"

typedef struct _net_if_std_ring {
    struct iovec *iovec;
    unsigned char *buf;
    unsigned int buf_size;
    unsigned int iov_head;
    unsigned int iov_max;
} net_if_std_ring_t;

typedef struct _net_if_std {
    char name[LUNE_MAX_SHORT_NAME_BUF_LEN];
#define NET_IF_STD_FLAG_ON(std, flag)           (((net_if_std_t *)(std))->flags & (flag))
#define NET_IF_STD_SET_FLAG(std, flag)          \
    do { ((net_if_std_t *)(std))->flags |= (flag); } while (0)
#define NET_IF_STD_CLEAR_FLAG(std, flag)        \
    do { ((net_if_std_t *)(std))->flags &= (~flag); } while (0)
#define NET_IF_STD_FLAG_UP                      0x00000001
#define NET_IF_STD_IS_UP(std)                   NET_IF_STD_FLAG_ON(std, NET_IF_STD_FLAG_UP)
#define NET_IF_STD_SET_UP(std)                  NET_IF_STD_SET_FLAG(std, NET_IF_STD_FLAG_UP)
#define NET_IF_STD_SET_DOWN(std)                NET_IF_STD_CLEAR_FLAG(std, NET_IF_STD_FLAG_UP)
#define NET_IF_STD_FLAG_LOSING_PKT              0x00000002
#define NET_IF_STD_IS_LOSING_PKT(std)           NET_IF_STD_FLAG_ON(std, NET_IF_STD_FLAG_LOSING_PKT)
#define NET_IF_STD_SET_LOSING_PKT(std)          NET_IF_STD_SET_FLAG(std, NET_IF_STD_FLAG_LOSING_PKT)
#define NET_IF_STD_CLEAR_LOSING_PKT(std)        NET_IF_STD_CLEAR_FLAG(std, NET_IF_STD_FLAG_LOSING_PKT)
#define NET_IF_STD_FLAG_IPV4                    0x00000004
#define NET_IF_STD_IS_IPV4_SET(std)             NET_IF_STD_FLAG_ON(std, NET_IF_STD_FLAG_IPV4)
#define NET_IF_STD_SET_IPV4(std)                NET_IF_STD_SET_FLAG(std, NET_IF_STD_FLAG_IPV4)
#define NET_IF_STD_CLEAR_IPV4(std)              NET_IF_STD_CLEAR_FLAG(std, NET_IF_STD_FLAG_IPV4)
#define NET_IF_STD_FLAG_MASK                    0x00000008
#define NET_IF_STD_IS_MASK_SET(std)             NET_IF_STD_FLAG_ON(std, NET_IF_STD_FLAG_MASK)
#define NET_IF_STD_SET_MASK(std)                NET_IF_STD_SET_FLAG(std, NET_IF_STD_FLAG_MASK)
#define NET_IF_STD_CLEAR_MASK(std)              NET_IF_STD_CLEAR_FLAG(std, NET_IF_STD_FLAG_MASK)
#define NET_IF_STD_FLAG_GW                      0x00000010
#define NET_IF_STD_IS_GW_SET(std)               NET_IF_STD_FLAG_ON(std, NET_IF_STD_FLAG_GW)
#define NET_IF_STD_SET_GW(std)                  NET_IF_STD_SET_FLAG(std, NET_IF_STD_FLAG_GW)
#define NET_IF_STD_CLEAR_GW(std)                NET_IF_STD_CLEAR_FLAG(std, NET_IF_STD_FLAG_GW)
    unsigned int flags;
    int fd;
    unsigned int tx_task_id;
    unsigned short mtu;
    unsigned short old_flags;
    lune_mac_addr_t mac;
    lune_ipv4_addr_t ipv4;
    lune_ipv4_addr_t mask;
    lune_ipv4_addr_t gw;
    net_if_std_ring_t send_ring;
    net_if_std_ring_t recv_ring;
    lune_net_if_stats_t stats;
    unsigned short kern_tp_mac;
    unsigned short kern_frame_size;
    lune_timer_t stats_tmr;
} net_if_std_t;

typedef struct _net_if_std_frm_tail {
#define NET_IF_STD_GAP_VAL                      (0xdeadbeef)
    unsigned int gap;
#define NET_IF_STD_READING                      (0xabcddcba)
#define NET_IF_STD_NOT_READING                  (0xdcbaabcd)
    unsigned int reading_flag;
} net_if_std_frm_tail_t;

#define NET_IF_STD_RING_IS_PKT_READABLE(ring)   \
    (TP_STATUS_USER & ((struct tpacket2_hdr *)((ring)->iovec)[(ring)->iov_head].iov_base)->tp_status)
#define NET_IF_STD_RING_IS_PKT_WRITABLE(ring)   \
    (TP_STATUS_AVAILABLE == ((struct tpacket2_hdr *)((ring)->iovec)[(ring)->iov_head].iov_base)->tp_status)
#define NET_IF_STD_RING_GET_TPKT_HDR(ring)      \
    (struct tpacket2_hdr *)(((ring)->iovec)[(ring)->iov_head].iov_base)
#define NET_IF_STD_RING_MOVE_NEXT(ring)         \
    do {                                        \
        (ring)->iov_head = ((ring)->iov_head == (ring)->iov_max) ? 0 : (ring)->iov_head + 1;    \
    } while (0)
#define NET_IF_STD_RING_BUF_SIZE                (64 * 1024 * 1024)

static int net_if_std_ring_init(net_if_std_t *std)
{
    unsigned int i, j, idx, frames_per_block, order;
    struct tpacket_req req;
    struct tpacket2_hdr *hdr;
    unsigned long ring_buf_size;
    struct iovec *send_iovec, *recv_iovec;

    req.tp_frame_size = TPACKET_ALIGN(TPACKET2_HDRLEN)
        + TPACKET_ALIGN(std->mtu + LUNE_ETH_HDR_LEN
        + LUNE_QINQ_FIELD_LEN + sizeof(net_if_std_frm_tail_t));

    ring_buf_size = NET_IF_STD_RING_BUF_SIZE;
    req.tp_block_size = TPACKET_ALIGN(TPACKET2_HDRLEN)
        + TPACKET_ALIGN(LUNE_NET_IF_MAX_MTU + LUNE_ETH_HDR_LEN
        + LUNE_QINQ_FIELD_LEN + sizeof(net_if_std_frm_tail_t));

    /* round up to nearest order of page size */
    for (order = 0; order <= 8; order++) {
        if ((unsigned int)(getpagesize() << order) >= req.tp_block_size) {
            break;
        }
    }

    req.tp_block_size = getpagesize() << order;
    req.tp_block_nr = ring_buf_size / req.tp_block_size;
    if (req.tp_block_nr * req.tp_block_size < ring_buf_size) {
        req.tp_block_nr++;
    }
    ring_buf_size = req.tp_block_nr * req.tp_block_size;

    frames_per_block = req.tp_block_size / req.tp_frame_size;
    req.tp_frame_nr = frames_per_block * req.tp_block_nr;

    if (setsockopt(std->fd, SOL_PACKET, PACKET_TX_RING, (void*)&req, sizeof(req))) {        
        lune_log(LUNE_CRIT,
            "failed to setsockopt PACKET_TX_RING on %s: %s", std->name, strerror(errno));
        ERR_SET_ERR(LUNE_ERR_SYS_SOCKET_ERR);
        goto ERR_1;
    }

    if (setsockopt(std->fd, SOL_PACKET, PACKET_RX_RING, (void*)&req, sizeof(req))) {        
        ERR_SET_ERR(LUNE_ERR_SYS_SOCKET_ERR);
        lune_log(LUNE_CRIT,
            "failed to setsockopt PACKET_RX_RING on %s: %s", std->name, strerror(errno));
        goto ERR_2;
    }

    send_iovec = (struct iovec *)lune_malloc_x(req.tp_frame_nr * sizeof(struct iovec));
    if (NULL == send_iovec) {
        lune_log(LUNE_CRIT,
            "failed to alloc memory while mmapping socket on %s: %s", std->name, strerror(errno));
        goto ERR_3;
    }

    recv_iovec = (struct iovec *)lune_malloc_x(req.tp_frame_nr * sizeof(struct iovec));
    if (NULL == recv_iovec) {
        lune_log(LUNE_CRIT,
            "failed to alloc memory while mmapping socket on %s: %s", std->name, strerror(errno));
        goto ERR_4;
    }

    std->recv_ring.buf = (void *)mmap(0,
        (size_t)2 * ring_buf_size, PROT_READ | PROT_WRITE, MAP_SHARED, std->fd, 0);
    if (MAP_FAILED == std->recv_ring.buf) {
        ERR_SET_ERR(LUNE_ERR_SYS_ERR);
        lune_log(LUNE_CRIT, "failed to mmap socket on %s: %s", std->name, strerror(errno));
        goto ERR_5;
    }

    std->send_ring.buf = std->recv_ring.buf + ring_buf_size;
    std->kern_frame_size = req.tp_frame_size;

    idx = 0;
    for (i = 0; i < req.tp_block_nr; i++) {
        for (j = 0; j < frames_per_block; j++) {
            net_if_std_frm_tail_t *tail;

            /* initialize send buffer */
            send_iovec[idx].iov_base = std->send_ring.buf + req.tp_block_size * i + j * req.tp_frame_size;
            send_iovec[idx].iov_len = req.tp_frame_size;
            hdr = (struct tpacket2_hdr *)send_iovec[idx].iov_base;
            hdr->tp_status = TP_STATUS_AVAILABLE;

            /* initialize receive buffer */
            recv_iovec[idx].iov_base = std->recv_ring.buf + req.tp_block_size * i + j * req.tp_frame_size;
            recv_iovec[idx].iov_len = req.tp_frame_size;
            hdr = (struct tpacket2_hdr *)recv_iovec[idx].iov_base;
            hdr->tp_status = TP_STATUS_KERNEL;
            tail = (net_if_std_frm_tail_t *)((unsigned char *)hdr
                + std->kern_frame_size - sizeof(net_if_std_frm_tail_t));
            tail->gap = NET_IF_STD_GAP_VAL;
            tail->reading_flag = NET_IF_STD_NOT_READING;

            idx++;
        }
    }

    std->send_ring.buf_size = ring_buf_size;
    std->send_ring.iov_head = 0;
    std->send_ring.iov_max = req.tp_frame_nr - 1;
    std->send_ring.iovec = send_iovec;

    std->recv_ring.buf_size = ring_buf_size;
    std->recv_ring.iov_head = 0;
    std->recv_ring.iov_max = req.tp_frame_nr - 1;
    std->recv_ring.iovec = recv_iovec;

    return 0;

ERR_5:
    lune_free_x(recv_iovec);

ERR_4:
    lune_free_x(send_iovec);

ERR_3:
    memset(&req, 0x00, sizeof(req));
    if (setsockopt(std->fd, SOL_PACKET, PACKET_RX_RING, (void *)&req, sizeof(req))) {
        lune_log(LUNE_WARN, "failed to setsockopt PACKET_RX_RING on %s: %s", std->name, strerror(errno));
    }

ERR_2:
    memset(&req, 0x00, sizeof(req));
    if (setsockopt(std->fd, SOL_PACKET, PACKET_TX_RING, (void *)&req, sizeof(req))) {
        lune_log(LUNE_WARN, "failed to setsockopt PACKET_TX_RING on %s: %s", std->name, strerror(errno));
    }

ERR_1:
    return ERR_GET_LAST_ERR();
}

static void net_if_std_ring_fini(net_if_std_t *std)
{
    struct tpacket_req req;

    std->kern_frame_size = 0;

    if (-1 == munmap(std->recv_ring.buf, std->recv_ring.buf_size << 1)) {
        lune_log(LUNE_WARN, "failed to munmap socket on %s: %s", std->name, strerror(errno));
    }

    lune_free_x(std->recv_ring.iovec);
    lune_free_x(std->send_ring.iovec);

    memset(&std->recv_ring, 0x00, sizeof(net_if_std_ring_t));
    memset(&std->send_ring, 0x00, sizeof(net_if_std_ring_t));

    memset(&req, 0x00, sizeof(req));
    if (setsockopt(std->fd, SOL_PACKET, PACKET_RX_RING, (void *)&req, sizeof(req))) {
        lune_log(LUNE_WARN, "failed to setsockopt PACKET_RX_RING on %s: %s", std->name, strerror(errno));
    }

    memset(&req, 0x00, sizeof(req));
    if (setsockopt(std->fd, SOL_PACKET, PACKET_TX_RING, (void *)&req, sizeof(req))) {
        lune_log(LUNE_WARN, "failed to setsockopt PACKET_TX_RING on %s: %s", std->name, strerror(errno));
    }
}

static int net_if_std_get_socket_flags(const char *name, unsigned short *pflags)
{
    struct ifreq ifr;
    int fd;

    if (-1 == (fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL)))) {
        lune_log(LUNE_CRIT, "failed to create raw socket on %s: %s", name, strerror(errno));
        return ERR_SET_ERR(LUNE_ERR_SYS_SOCKET_ERR);
    }

    memset(&ifr, 0x00, sizeof (ifr));
    strcpy(ifr.ifr_name, name);

    if (ioctl(fd, SIOCGIFFLAGS, &ifr) < 0) {
        lune_log(LUNE_CRIT, "failed to get flags on %s: %s", name, strerror(errno));
        close(fd);
        return ERR_SET_ERR(LUNE_ERR_SYS_SOCKET_ERR);
    }

    *pflags = ifr.ifr_flags;

    close(fd);
    return 0;
}

static int net_if_std_set_socket_flags(const char *name, unsigned short flags)
{
    struct ifreq ifr;
    int fd;

    if (-1 == (fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL)))) {
        lune_log(LUNE_CRIT, "failed to create raw socket on %s: %s", name, strerror(errno));
        return ERR_SET_ERR(LUNE_ERR_SYS_SOCKET_ERR);
    }

    memset(&ifr, 0x00, sizeof (ifr));
    strcpy(ifr.ifr_name, name);
    ifr.ifr_flags = flags;

    if (ioctl(fd, SIOCSIFFLAGS, &ifr) < 0) {
        lune_log(LUNE_CRIT, "failed to set flags on %s: %s", name, strerror(errno));
        close(fd);
        return ERR_SET_ERR(LUNE_ERR_SYS_SOCKET_ERR);
    }

    close(fd);
    return 0;
}

#define RTF_UP          0x0001  /* route is valid */
#define RTF_GATEWAY     0x0002  /* destination is a gateway */

static int get_ipv4_gateway(const char *net_if_name, struct in_addr *gw) {
    FILE *fp;
    char line[256];
    char name[16];
    unsigned int dst, mask;
    int metric, refcnt, use, flags, mtu, window, irtt;

    fp = fopen("/proc/net/route", "r");
    if (NULL == fp) {
        return -1;
    }

    /* skip the header line */
    fgets(line, sizeof(line), fp);

    while (NULL != fgets(line, sizeof(line), fp)) {
        if (11 == sscanf(line, "%s %x %x %x %d %d %d %x %d %d %d",
            name, &dst, &gw->s_addr, &flags, &refcnt, &use, &metric, &mask, &mtu, &window, &irtt)) {
            /* check if it's the default route (destination 0.0.0.0) and for the correct interface */
            if (0 == dst && (flags & RTF_UP) && (flags & RTF_GATEWAY) && !strcmp(name, net_if_name)) {
                fclose(fp);
                return 0;
            }
        }
    }

    fclose(fp);
    return -1;
}

static int net_if_std_init_std(net_if_std_t *std, const char *name)
{
    struct ifreq ifr;
    int fd;

    strcpy(std->name, name);
    std->flags = 0;
    std->fd = -1;
    std->tx_task_id = LUNE_INVALID_ID;

    /* create temporary socket to get mtu */
    if (-1 == (fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL)))) {
        lune_log(LUNE_CRIT, "failed to create raw socket on %s: %s", std->name, strerror(errno));
        ERR_SET_ERR(LUNE_ERR_SYS_SOCKET_ERR);
        goto ERR_1;
    }

    memset(&ifr, 0x00, sizeof(ifr));
    strcpy(ifr.ifr_name, std->name);


    /* get mtu */
    if (-1 == ioctl(fd, SIOCGIFMTU, &ifr)) {
        lune_log(LUNE_CRIT, "failed to get mtu on %s: %s", std->name, strerror(errno));
        ERR_SET_ERR(LUNE_ERR_SYS_SOCKET_ERR);
        goto ERR_2;
    }
    std->mtu = (unsigned short)ifr.ifr_mtu;
    std->old_flags = 0;

    /* get mac address */
    if (-1 == ioctl(fd, SIOCGIFHWADDR, &ifr)) {
        lune_log(LUNE_CRIT, "failed to get mac on %s: %s", std->name, strerror(errno));
        ERR_SET_ERR(LUNE_ERR_SYS_SOCKET_ERR);
        goto ERR_2;
    }
    LUNE_MAC_CPY(std->mac, (unsigned char *)ifr.ifr_hwaddr.sa_data);

    /* get ip address */
    if (0 == ioctl(fd, SIOCGIFADDR, &ifr)) {
        std->ipv4 = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr;
        NET_IF_STD_SET_IPV4(std);
    }

    /* get subnet mask */
    if (0 == ioctl(fd, SIOCGIFNETMASK, &ifr)) {
        std->mask = ((struct sockaddr_in *)&ifr.ifr_netmask)->sin_addr.s_addr;
        NET_IF_STD_SET_MASK(std);
    }

    /* get gateway */
    struct in_addr gw;
    if (0 == get_ipv4_gateway(name, &gw)) {
        std->gw = gw.s_addr;
        NET_IF_STD_SET_GW(std);
    }

    memset(&std->send_ring, 0x00, sizeof(net_if_std_ring_t));
    memset(&std->recv_ring, 0x00, sizeof(net_if_std_ring_t));
    memset(&std->stats, 0x00, sizeof(lune_net_if_stats_t));

    return 0;

ERR_2:
    close(fd);

ERR_1:
    return ERR_GET_LAST_ERR();
}

static int net_if_std_add_net_if(net_if_t *ifp __attribute__((unused)),
    const char *name, const void *conf_val, unsigned int conf_len, void **pdata)
{
    net_if_std_t *std;
    int err;

    if (conf_val != NULL || conf_len != 0) {
        err = ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        goto ERR_1;
    }

    if (NULL == (std = lune_malloc(sizeof(net_if_std_t)))) {
        err = ERR_GET_LAST_ERR();
        goto ERR_1;
    }

    if (0 != (err = net_if_std_init_std(std, name))) {
        goto ERR_2;
    }

    *pdata = std;
    return 0;

ERR_2:
    lune_free(std);

ERR_1:
    return err;
}

static int net_if_std_del_net_if(net_if_std_t *std)
{
    lune_free(std);
    return 0;
}

static int net_if_std_is_up(net_if_std_t *std)
{
    return NET_IF_STD_IS_UP(std);
}

static void net_if_std_send_tx_ring(void *arg)
{
    net_if_std_t *std = (net_if_std_t *)arg;
    int err;

    if (0 > (err = send(std->fd, NULL, 0, MSG_DONTWAIT))) {
        lune_log(LUNE_CRIT, "failed to send packets on %s: %s", std->name, strerror(errno));
        ERR_SET_ERR(LUNE_ERR_SYS_SOCKET_ERR);
    }
}

static void net_if_std_stats_timer_func(net_if_std_t *std)
{
    struct tpacket_stats stats;
    socklen_t len = sizeof(stats);

    if (getsockopt(std->fd, SOL_PACKET, PACKET_STATISTICS, &stats, &len) < 0) {
        lune_log(LUNE_INFO, "failed to get packet statistics on %s", std->name);
        return;
    }

    std->stats.pkt_in_dropped += stats.tp_drops;

#ifdef LUNE_DEBUG
    lune_log(LUNE_DBG, "%s AF_PACKET statistics: tp_packets %d tp_drops %d",
        std->name, stats.tp_packets, stats.tp_drops);
#endif
}

static int net_if_std_set_up(net_if_std_t *std)
{
    struct ifreq ifr;
    struct sockaddr_ll sockaddr;
    unsigned short flags, old_flags = 0;

    if (net_if_std_get_socket_flags(std->name, &old_flags)) {
        goto ERR_1;
    }

    if (!((old_flags & IFF_UP) && (old_flags & IFF_RUNNING))) {
        flags = (old_flags | IFF_UP | IFF_RUNNING);
        if (net_if_std_set_socket_flags(std->name, flags)) {
            goto ERR_1;
        }
    }

    /* create send/recv socket */
    if (-1 == (std->fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL)))) {
        lune_log(LUNE_CRIT, "failed to create raw socket on %s: %s", std->name, strerror(errno));
        ERR_SET_ERR(LUNE_ERR_SYS_SOCKET_ERR);
        goto ERR_2;
    }

    /* get index */
    memset(&ifr, 0x00, sizeof(ifr)); 
    strcpy(ifr.ifr_name, std->name);
    if (-1 == ioctl(std->fd, SIOCGIFINDEX, &ifr) || -1 == ifr.ifr_ifindex) {
        lune_log(LUNE_CRIT, "failed to get index on %s: %s", std->name, strerror(errno));
        ERR_SET_ERR(LUNE_ERR_SYS_SOCKET_ERR);
        goto ERR_3;
    }

    /* set promiscuous mode */
    struct packet_mreq mr;
    memset(&mr, 0x00, sizeof(mr));
    mr.mr_ifindex = ifr.ifr_ifindex;
    mr.mr_type = PACKET_MR_PROMISC;
    if (0 != setsockopt(std->fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof(mr))) {
        lune_log(LUNE_CRIT, "failed to set promiscuous mode on %s: %s", std->name, strerror(errno));
        ERR_SET_ERR(LUNE_ERR_SYS_SOCKET_ERR);
        goto ERR_3;
    }

    /* set packet version */
    int ver = TPACKET_V2;
    if (0 != setsockopt(std->fd, SOL_PACKET, PACKET_VERSION, &ver, sizeof(ver))) {
        lune_log(LUNE_CRIT, "failed to set packet version on %s: %s", std->name, strerror(errno));
        ERR_SET_ERR(LUNE_ERR_SYS_SOCKET_ERR);
        goto ERR_3;
    }

    /* set sockadddr */
    memset(&sockaddr, 0x00, sizeof(struct sockaddr_ll));
    sockaddr.sll_family = AF_PACKET;
    sockaddr.sll_ifindex = ifr.ifr_ifindex;
    sockaddr.sll_protocol  = htons(ETH_P_ALL);

    if (bind(std->fd, (struct sockaddr *)&sockaddr, sizeof(sockaddr)) != 0) {
        lune_log(LUNE_CRIT, "failed to bind socket on %s: %s", std->name, strerror(errno));
        ERR_SET_ERR(LUNE_ERR_SYS_SOCKET_ERR);
        goto ERR_3;
    }

    /* verify mtu consistency */
    memset(&ifr, 0x00, sizeof(ifr));
    strcpy(ifr.ifr_name, std->name);
    if (-1 == ioctl(std->fd, SIOCGIFMTU, &ifr)) {
        lune_log(LUNE_CRIT, "failed to get mtu on %s: %s", std->name, strerror(errno));
        ERR_SET_ERR(LUNE_ERR_SYS_SOCKET_ERR);
        goto ERR_3;
    }

    if (ifr.ifr_mtu != std->mtu) {
        lune_log(LUNE_CRIT, "mtu has changed since being added on %s", std->name);
        ERR_SET_ERR(LUNE_ERR_NET_IF_INCONSISTENT_MTU);
        goto ERR_3;
    }

    if (net_if_std_ring_init(std)) {
        goto ERR_3;
    }

    if (LUNE_INVALID_ID == (std->tx_task_id = sched_add_task(std->name,
        net_if_std_send_tx_ring, (void *)std, SCHED_PRIO_SEND))) {
        lune_log(LUNE_CRIT, "failed to add send task on %s: %s", std->name, ERR_GET_LAST_ERR_STR());
        goto ERR_4;        
    }

    NET_IF_STD_SET_UP(std);
    std->old_flags = old_flags;
    std->kern_tp_mac = 0;

    timer_init_timer(&std->stats_tmr, LUNE_TIMER_RECURRING,
        LUNE_TIMER_RES_HIGH, (lune_timer_func_t)net_if_std_stats_timer_func, std);
    timer_add_timer(&std->stats_tmr, 1 * LUNE_TIME_SECOND);

    return 0;

ERR_4:
    net_if_std_ring_fini(std);

ERR_3:
    close(std->fd);
    std->fd = -1;

ERR_2:
    if (!((old_flags & IFF_UP) && (old_flags & IFF_RUNNING))) {
        (void)net_if_std_set_socket_flags(std->name, old_flags);
    }

ERR_1:
    return ERR_GET_LAST_ERR();
}

static int net_if_std_set_down(net_if_std_t *std)
{
    NET_IF_STD_SET_DOWN(std);

    lune_assert(LUNE_TIMER_IS_ADDED(std->stats_tmr));
    lune_assert(!lune_del_timer(&std->stats_tmr));

    lune_assert(!sched_del_task(std->tx_task_id));
    std->tx_task_id = LUNE_INVALID_ID;

    net_if_std_ring_fini(std);

    close(std->fd);
    std->fd = -1;

    if (!((std->old_flags & IFF_UP) && (std->old_flags & IFF_RUNNING))) {
        (void)net_if_std_set_socket_flags(std->name, std->old_flags);
    }

    std->old_flags = 0;
    std->kern_tp_mac = 0;

    return 0;
}

static int net_if_std_send(net_if_std_t *std, const unsigned char *buf, unsigned int len)
{
    net_if_std_ring_t *ring = &std->send_ring;
    struct tpacket2_hdr *hdr;

    if (!NET_IF_STD_RING_IS_PKT_WRITABLE(ring)) {
        return ERR_SET_ERR(LUNE_ERR_BUF_FULL);
    }

    hdr = NET_IF_STD_RING_GET_TPKT_HDR(ring);
    hdr->tp_len = len;
    memcpy((unsigned char *)hdr + TPACKET_ALIGN(sizeof(struct tpacket2_hdr)), buf, len);
    hdr->tp_status = TP_STATUS_SEND_REQUEST;

    std->stats.byte_out += len;
    std->stats.pkt_out++;

    NET_IF_STD_RING_MOVE_NEXT(ring);

    return 0;
}

static int net_if_std_recv(net_if_std_t *std, unsigned char **pbuf, unsigned int *plen)
{
    net_if_std_ring_t *ring = &std->recv_ring;
    struct tpacket2_hdr *hdr;
    net_if_std_frm_tail_t *tail;

    if (!NET_IF_STD_RING_IS_PKT_READABLE(ring)) {
        /* ERR_SET_ERR() unneeded */
        return -LUNE_ERR_NET_IF_NO_PKT;
    }

    /* packet received by kernel and status is set to TP_STATUS_USER */
    hdr = NET_IF_STD_RING_GET_TPKT_HDR(ring);
    tail = (net_if_std_frm_tail_t *)((unsigned char *)hdr + std->kern_frame_size - sizeof(net_if_std_frm_tail_t));
    if (unlikely(NET_IF_STD_READING == tail->reading_flag)) {
        /*
            buffer full due to channel recv() unable to catch up with aggregator recv()
            wait till channel recv() is done
        */
        lune_log_once(LUNE_INFO, "incoming buffer full on %s", std->name);
        lune_assert(NET_IF_STD_GAP_VAL == tail->gap);
        /* ERR_SET_ERR() unneeded */
        return -LUNE_ERR_NET_IF_NO_PKT;
    }

    lune_assert(NET_IF_STD_GAP_VAL == tail->gap);
    lune_assert(NET_IF_STD_NOT_READING == tail->reading_flag);

    tail->reading_flag = NET_IF_STD_READING;

    if (hdr->tp_status & TP_STATUS_LOSING) {
        if (!NET_IF_STD_IS_LOSING_PKT(std)) {
            /* set flag so log only once */
            NET_IF_STD_SET_LOSING_PKT(std);
            lune_log(LUNE_INFO, "packet dropped on %s", std->name);
        }
    } else {
        if (NET_IF_STD_IS_LOSING_PKT(std)) {
            /* clear flag */
            NET_IF_STD_CLEAR_LOSING_PKT(std);
        }
    }

    if (unlikely(hdr->tp_mac != std->kern_tp_mac)) {
        if (0 == std->kern_tp_mac) {
            /* store tp_mac */
            std->kern_tp_mac = hdr->tp_mac;
        } else {
            /* inconsistency of tp_mac */
            lune_log(LUNE_WARN, "unexpected tp_mac: %d expected but %d received on %s: %s",
                std->kern_tp_mac, hdr->tp_mac, std->name, ERR_GET_ERR_STR(ERR_SET_ERR(LUNE_ERR_NET_IF_INTERNAL)));
            return ERR_GET_LAST_ERR();
        }
    }

    *pbuf = (unsigned char *)hdr + hdr->tp_mac;
    *plen = hdr->tp_len;

    std->stats.byte_in += hdr->tp_len;
    std->stats.pkt_in++;

    return 0;
}

static void net_if_std_recv_done(net_if_std_t *std)
{
    net_if_std_ring_t *ring = &std->recv_ring;
    struct tpacket2_hdr *hdr = NET_IF_STD_RING_GET_TPKT_HDR(ring);
    net_if_std_frm_tail_t *tail = (net_if_std_frm_tail_t *)((unsigned char *)hdr
        + std->kern_frame_size - sizeof(net_if_std_frm_tail_t));

    lune_assert(NET_IF_STD_GAP_VAL == tail->gap);

    tail->reading_flag = NET_IF_STD_NOT_READING;
    hdr->tp_status = TP_STATUS_KERNEL;

    NET_IF_STD_RING_MOVE_NEXT(ring);
}

static void net_if_std_recv_fwd_pkt(net_if_std_t *std, void **pdata)
{
    *pdata = NULL;
    NET_IF_STD_RING_MOVE_NEXT(&std->recv_ring);
}

static void net_if_std_recv_free_pkt(net_if_std_t *std, unsigned char *buf, void *data)
{
    struct tpacket2_hdr *hdr = (struct tpacket2_hdr *)(buf - std->kern_tp_mac);
    net_if_std_frm_tail_t *tail = (net_if_std_frm_tail_t *)((unsigned char *)hdr
        + std->kern_frame_size - sizeof(net_if_std_frm_tail_t));

    lune_assert(NULL == data);
    lune_assert(NET_IF_STD_GAP_VAL == tail->gap);

    tail->reading_flag = NET_IF_STD_NOT_READING;
    hdr->tp_status = TP_STATUS_KERNEL;
}

static int net_if_std_get_opt(net_if_std_t *std,
    net_if_opt_en opt, unsigned char *opt_val, unsigned int opt_len)
{
    lune_assert(NULL != opt_val);

    switch (opt) {
    case NET_IF_OPT_GET_HW_CSUM:
        if (opt_len != sizeof(unsigned short)) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        *(unsigned short *)opt_val = 0;
        break;
    case NET_IF_OPT_GET_MAX_DATA_RATE:
        /*
            always asked while new interface being added, no need to report error
        */
        return -LUNE_ERR_NOT_SUPPORTED;
    case NET_IF_OPT_GET_MTU:
        if (opt_len != sizeof(unsigned short)) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        *(unsigned short *)opt_val = std->mtu;
        break;
    case NET_IF_OPT_GET_MAC:
        if (opt_len != LUNE_MAC_ADDR_LEN) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        LUNE_MAC_CPY(opt_val, std->mac);
        break;
    case NET_IF_OPT_GET_IPV4:
        if (opt_len != LUNE_IPV4_ADDR_LEN) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        if (!NET_IF_STD_IS_IPV4_SET(std)) {
            /*
                ERR_SET_ERR() unneeded as it is normal that ipv4 address is not set
                on a standard network interface
            */
            return -LUNE_ERR_NOT_SET;
        }

        *(lune_ipv4_addr_t *)opt_val = std->ipv4;
        break;
    case NET_IF_OPT_GET_MASK:
        if (opt_len != LUNE_IPV4_ADDR_LEN) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        if (!NET_IF_STD_IS_MASK_SET(std)) {
            /*
                ERR_SET_ERR() unneeded as it is normal that subnet mask is not set
                on a standard network interface
            */
            return -LUNE_ERR_NOT_SET;
        }

        *(lune_ipv4_addr_t *)opt_val = std->mask;
        break;
    case NET_IF_OPT_GET_GW:
        if (opt_len != LUNE_IPV4_ADDR_LEN) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        if (!NET_IF_STD_IS_GW_SET(std)) {
            /*
                ERR_SET_ERR() unneeded as it is normal that subnet mask is not set
                on a standard network interface
            */
            return -LUNE_ERR_NOT_SET;
        }

        *(lune_ipv4_addr_t *)opt_val = std->gw;
        break;
    case NET_IF_OPT_GET_STATS:
        if (opt_len != sizeof(lune_net_if_stats_t)) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }

        memcpy(opt_val, &std->stats, sizeof(lune_net_if_stats_t));
        break;
    default:
        return ERR_SET_ERR(LUNE_ERR_NOT_SUPPORTED);
    }

    return 0;
}

static int net_if_std_set_mtu(net_if_std_t *std, unsigned short mtu)
{
    int fd;
    struct ifreq ifr;

    if (-1 == (fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL)))) {
        lune_log(LUNE_CRIT, "failed to create raw socket on %s: %s", std->name, strerror(errno));
        return ERR_SET_ERR(LUNE_ERR_SYS_SOCKET_ERR);
    }

    memset(&ifr, 0x00, sizeof(ifr));
    strcpy(ifr.ifr_name, std->name);
    ifr.ifr_mtu = mtu;

    if (ioctl(fd, SIOCSIFMTU, &ifr)<0) {
        lune_log(LUNE_CRIT, "failed to set mtu on %s: %s", std->name, strerror(errno));
        close(fd);
        return ERR_SET_ERR(LUNE_ERR_SYS_SOCKET_ERR);
    }

    close(fd);
    std->mtu = mtu;

    return 0;
}

static int net_if_std_set_opt(net_if_std_t *std,
    net_if_opt_en opt,
    unsigned char *opt_val,
    unsigned int opt_len __attribute__((unused)))
{
    lune_assert(NULL != opt_val);

    switch (opt) {
    case NET_IF_OPT_SET_MTU:
        return net_if_std_set_mtu(std, *(unsigned short *)opt_val);
    case NET_IF_OPT_DISABLE_HW_CSUM:
        lune_log(LUNE_INFO, "checksum offload not supported on %s", std->name);
        /* fall through */
    default:
        return ERR_SET_ERR(LUNE_ERR_NOT_SUPPORTED);
    }

    return 0;
}

net_if_drv_t g_net_if_drv_std = {
    .type = LUNE_NET_IF_STD,
    .name = "standard",
    .add_net_if = (net_if_add_net_if_func_t)net_if_std_add_net_if,
    .del_net_if = (net_if_del_net_if_func_t)net_if_std_del_net_if,
    .is_up = (net_if_is_up_func_t)net_if_std_is_up,
    .set_up = (net_if_set_up_func_t)net_if_std_set_up,
    .set_down = (net_if_set_down_func_t)net_if_std_set_down,
    .send = (net_if_send_func_t)net_if_std_send,
    .send_pkts = NULL,
    .recv = (net_if_recv_func_t)net_if_std_recv,
    .recv_pkts = NULL,
    .recv_done = (net_if_recv_done_func_t)net_if_std_recv_done,
    .recv_fwd_pkt = (net_if_recv_fwd_pkt_func_t)net_if_std_recv_fwd_pkt,
    .recv_free_pkt = (net_if_recv_free_pkt_func_t)net_if_std_recv_free_pkt,
    .get_opt = (net_if_get_opt_func_t)net_if_std_get_opt,
    .set_opt = (net_if_set_opt_func_t)net_if_std_set_opt,
};
