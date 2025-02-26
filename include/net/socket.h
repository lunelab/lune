/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2024 Lune Reseau, Inc.
 */

#ifndef __SOCKET_OPS__
#define __SOCKET_OPS__
typedef struct _socket_ops socket_ops_t;
typedef struct _socket socket_t;
typedef struct _socket_x socket_x_t;
#endif

#ifndef __SOCKET_H__
#define __SOCKET_H__

#include "lune/mem.h"
#include "lune/socket.h"

#include "drv/net_if.h"
#include "net/mac.h"
#include "net/icmp.h"
#include "net/igmp.h"
#include "net/ip.h"
#ifdef LUNE_BUILD_SSL
#include "net/ssl.h"
#endif
#include "net/tcp.h"
#include "net/udp.h"

#define SOCKET_HTABLE_SIZE_IN_BIT           (22)
#define SOCKET_HTABLE_SIZE                  (1 << (SOCKET_HTABLE_SIZE_IN_BIT))
#define SOCKET_HTABLE_MASK                  (SOCKET_HTABLE_SIZE - 1)

#define SOCKET_LISTEN_HTABLE_SIZE_IN_BIT    (20)
#define SOCKET_LISTEN_HTABLE_SIZE           (1 << (SOCKET_LISTEN_HTABLE_SIZE_IN_BIT))
#define SOCKET_LISTEN_HTABLE_MASK           (SOCKET_LISTEN_HTABLE_SIZE - 1)

#define SOCKET_BASE                         \
    dlist_node_t node;                      \
    socket_ops_t *ops;                      \
    unsigned int id;                        \
    unsigned int rsvd_hdr_len;              \
    int ref_cnt;                            \
    unsigned int flags;                     \
    lune_socket_type_en type;

/* protocol control block */
typedef union _socket_pcb {
    net_if_pcb_t net_if;
    mac_pcb_t mac;
    ip_pcb_t ip;
    ipv4_pcb_t ipv4;
    ipv6_pcb_t ipv6;
    tcp_listen_pcb_t tcp_listen;
    udp_pcb_t udp;
    icmp_pcb_t icmp;
    igmp_pcb_t igmp;
#ifdef LUNE_BUILD_SSL
    ssl_pcb_t ssl;
    ssl_listen_pcb_t ssl_listen;
#endif
} socket_pcb_un;

typedef union _socket_x_pcb {
    tcp_pcb_t tcp;
} socket_x_pcb_un;

#define SOCKET_GET_ID(sk)                   (((struct _socket *)(sk))->id)
#define SOCKET_GET_TYPE(sk)                 (((struct _socket *)(sk))->type)
#define SOCKET_GET_SK_BY_PCB(p)             \
    ((struct _socket *)((unsigned char *)(p) - offsetof(struct _socket, pcb)))

#define SOCKET_X_GET_ID(sk)                 (((struct _socket_x *)(sk))->id)
#define SOCKET_X_GET_SK_BY_PCB(p)           \
    ((struct _socket_x *)((unsigned char *)(p) - offsetof(struct _socket_x, pcb)))

#define SOCKET_CLOSE_FLAG                   0x0001
#define SOCKET_CLOSE_ON(sk)                 ((sk)->flags & SOCKET_CLOSE_FLAG)
#define SOCKET_CLOSE_SET_ON(sk)             \
    do { (sk)->flags = ((sk)->flags | (SOCKET_CLOSE_FLAG)); } while (0)
#define SOCKET_CLOSE_SET_OFF(sk)            \
    do { (sk)->flags = ((sk)->flags & (~SOCKET_CLOSE_FLAG)); } while (0)

typedef struct _socket {
    SOCKET_BASE;
    socket_pcb_un pcb;
} socket_t;

typedef struct _socket_x {
    SOCKET_BASE;
    socket_x_pcb_un pcb;
} socket_x_t;

typedef int (*socket_create_func_t)(socket_t *);
typedef int (*socket_bind_func_t)(socket_t *, const void *, unsigned int);
typedef int (*socket_connect_func_t)(socket_t *, const void *, unsigned int);
typedef int (*socket_listen_func_t)(socket_t *, unsigned int);
typedef int (*socket_send_func_t)(socket_t *, const unsigned char *, unsigned int);
typedef int (*socket_send_pkts_func_t)(socket_t *,
    lune_socket_send_pkt_t *, unsigned int, unsigned int);
typedef int (*socket_sendto_func_t)(socket_t *, const unsigned char *,
    unsigned int, const void *, unsigned int, const void *, unsigned int);
typedef int (*socket_get_opt_func_t)(socket_t *,
    lune_socket_opt_en, unsigned char *, unsigned int);
typedef int (*socket_set_opt_func_t)(socket_t *,
    lune_socket_opt_en, const unsigned char *, unsigned int);
typedef int (*socket_close_func_t)(socket_t *);
typedef unsigned int (*socket_hash_func_t)(socket_pcb_un *);
typedef int (*socket_compare_func_t)(socket_pcb_un *, socket_pcb_un *);
typedef unsigned short (*socket_get_max_hdr_len_func_t)(socket_t *);

typedef struct _socket_ops {
    socket_create_func_t create;
    socket_bind_func_t bind;
    socket_connect_func_t connect;
    socket_listen_func_t listen;
    socket_send_func_t send;
    socket_send_pkts_func_t send_pkts;
    socket_sendto_func_t sendto;
    socket_get_opt_func_t get_opt;
    socket_set_opt_func_t set_opt;
    socket_close_func_t close;
    socket_hash_func_t hash;
    socket_compare_func_t compare;
    socket_get_max_hdr_len_func_t get_max_hdr_len;
} socket_ops_t;

#define SOCKET_PUSH_CB_SK(sk)                                                   \
    do {                                                                        \
        g_socket_cb_sk_stack[g_socket_cb_sk_stack_offset++] = (socket_t *)(sk); \
        lune_assert(g_socket_cb_sk_stack_offset <= SOCKET_CB_SK_STACK_SIZE);    \
    } while (0)
#define SOCKET_POP_CB_SK()                                                      \
    do {                                                                        \
        g_socket_cb_sk_stack[--g_socket_cb_sk_stack_offset] = NULL;             \
        lune_assert(g_socket_cb_sk_stack_offset >= 0);                          \
    } while (0)
#define SOCKET_GET_CB_SK()          g_socket_cb_sk_stack[g_socket_cb_sk_stack_offset - 1]

#define SOCKET_CB_SK_STACK_SIZE     (4)
extern __thread socket_t *g_socket_cb_sk_stack[SOCKET_CB_SK_STACK_SIZE];
extern __thread int g_socket_cb_sk_stack_offset;
extern __thread void *g_socket_socket_mem_pool;
extern __thread void *g_socket_socket_x_mem_pool;

#ifdef LUNE_DEBUG

#define socket_hold(sk)                     __socket_hold((socket_t *)sk, __FILE__, __LINE__)
#define socket_put(sk)                      __socket_put((socket_t *)sk, __FILE__, __LINE__)

static inline void __socket_hold(socket_t *sk,
    const char *file_name __attribute__((unused)), int line_no __attribute__((unused)))
{
    lune_assert(sk->ref_cnt >= 0);
    ++sk->ref_cnt;
}

static inline void __socket_put(socket_t *sk,
    const char *file_name __attribute__((unused)), int line_no __attribute__((unused)))
{
    lune_assert(sk->ref_cnt > 0);
    if (0 == --sk->ref_cnt) {
        if (LUNE_SOCKET_TCP == sk->type) {
            lune_mem_pool_free(g_socket_socket_x_mem_pool, sk);
        } else {
            lune_mem_pool_free(g_socket_socket_mem_pool, sk);
        }
    }
}

#else

#define socket_hold(sk)                     __socket_hold((socket_t *)sk)
#define socket_put(sk)                      __socket_put((socket_t *)sk)

static inline void __socket_hold(socket_t *sk)
{
    ++sk->ref_cnt;
}

static inline void __socket_put(socket_t *sk)
{
    if (0 == --sk->ref_cnt) {
        if (LUNE_SOCKET_TCP == sk->type) {
            lune_mem_pool_free(g_socket_socket_x_mem_pool, sk);
        } else {
            lune_mem_pool_free(g_socket_socket_mem_pool, sk);
        }
    }
}

#endif

#define socket_find(sk)                     __socket_find((socket_t *)sk)
#define socket_remove(sk)                   __socket_remove((socket_t *)sk)
#define socket_insert(sk)                   __socket_insert((socket_t *)sk)
#define socket_is_added(sk)                 __socket_is_added((socket_t *)sk)
#define socket_close(sk)                    __socket_close((socket_t *)sk)

socket_ops_t *socket_get_socket_ops(lune_socket_type_en type);

int socket_local_init(void);
void socket_local_fini(void);

socket_t *__socket_find(socket_t *sk);
int __socket_remove(socket_t *sk);
int __socket_insert(socket_t *sk);
int __socket_is_added(socket_t *sk);

socket_t *socket_listen_socket_find(socket_t *sk);
int socket_listen_socket_remove(socket_t *sk);
int socket_listen_socket_insert(socket_t *sk);
int socket_is_listen_socket_added(socket_t *sk);

socket_t *socket_create(lune_socket_type_en type);
int __socket_close(socket_t *sk);

socket_t *socket_get(unsigned int id);

#define SOCKET_IS_CLOSED(sk)    SOCKET_CLOSE_ON(sk)

#endif