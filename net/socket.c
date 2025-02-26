/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2024 Lune Reseau, Inc.
 */

#include "lune/assert.h"
#include "lune/err.h"
#include "lune/log.h"
#include "lune/mem.h"

#include "kernel/sched.h"
#include "lib/htable.h"
#include "lib/idlist.h"
#include "lib/idtable.h"
#include "net/socket.h"

static __thread void *s_socket_idlist = NULL;
static __thread void *s_socket_idtable = NULL;
static __thread void *s_socket_htable = NULL;
static __thread void *s_socket_listen_socket_htable = NULL;

__thread socket_t *g_socket_cb_sk_stack[SOCKET_CB_SK_STACK_SIZE];
__thread int g_socket_cb_sk_stack_offset;
__thread void *g_socket_socket_mem_pool;
__thread void *g_socket_socket_x_mem_pool;

static __thread socket_ops_t s_socket_ops_array[LUNE_SOCKET_MAX] = {{0}};

static void socket_register_socket_ops(lune_socket_type_en type, socket_ops_t *ops)
{
    lune_assert(NULL != ops);
    lune_assert(LUNE_SOCKET_MAX > type);

    lune_assert(NULL != ops->create);
    lune_assert(NULL != ops->bind);
    lune_assert(NULL != ops->close);

    memcpy(&s_socket_ops_array[type], ops, sizeof(socket_ops_t));
}

static int socket_hash(socket_t *sk)
{
    return sk->ops->hash(&sk->pcb);
}

static int socket_compare(socket_t *sk1, socket_t *sk2)
{
    if (sk1->type != sk2->type) {
        return 1;
    }

    return sk1->ops->compare(&sk1->pcb, &sk2->pcb);
}

static void socket_free(socket_t *sk)
{
    socket_put(sk);
}

socket_ops_t *socket_get_socket_ops(lune_socket_type_en type)
{
    lune_assert(LUNE_SOCKET_MAX > type);

    return &s_socket_ops_array[type];
}

int socket_local_init(void)
{
    if (NULL == (g_socket_socket_mem_pool = lune_create_mem_pool("socket", sizeof(socket_t)))) {
        goto ERR_1;
    }

    if (NULL == (g_socket_socket_x_mem_pool = lune_create_mem_pool("large socket", sizeof(socket_x_t)))) {
        goto ERR_2;
    }

    if (NULL == (s_socket_idlist = idlist_create_list("socket id list"))) {
        goto ERR_3;
    }

    if (NULL == (s_socket_idtable = idtable_create_table("socket id table",
        (idtable_free_func_t)socket_free,
        IDTABLE_MAX_TABLE_SIZE))) {
        goto ERR_4;
    }

    if (NULL == (s_socket_htable = htable_create_table("socket hash table", 
        (htable_hash_func_t)socket_hash,
        (htable_compare_func_t)socket_compare,
        (htable_free_func_t)socket_free,
        offsetof(socket_t, node),
        SOCKET_HTABLE_SIZE,
        0))) {
        goto ERR_5;
    }

    if (NULL == (s_socket_listen_socket_htable = htable_create_table("listen socket hash table", 
        (htable_hash_func_t)socket_hash,
        (htable_compare_func_t)socket_compare,
        (htable_free_func_t)socket_free,
        offsetof(socket_t, node),
        SOCKET_LISTEN_HTABLE_SIZE,
        0))) {
        goto ERR_6;
    }

    socket_register_socket_ops(LUNE_SOCKET_NET_IF, &g_socket_ops_net_if);
    socket_register_socket_ops(LUNE_SOCKET_MAC, &g_socket_ops_mac);
    socket_register_socket_ops(LUNE_SOCKET_IP, &g_socket_ops_ip);
    socket_register_socket_ops(LUNE_SOCKET_IPV4, &g_socket_ops_ipv4);
    socket_register_socket_ops(LUNE_SOCKET_IPV6, &g_socket_ops_ipv6);
    socket_register_socket_ops(LUNE_SOCKET_TCP, &g_socket_ops_tcp);
    socket_register_socket_ops(LUNE_SOCKET_TCP_LISTEN, &g_socket_ops_tcp_listen);
    socket_register_socket_ops(LUNE_SOCKET_TCP_BATCH_LISTEN,
        &g_socket_ops_tcp_batch_listen);
    socket_register_socket_ops(LUNE_SOCKET_TCP_PEER_LISTEN,
        &g_socket_ops_tcp_peer_listen);
    socket_register_socket_ops(LUNE_SOCKET_UDP, &g_socket_ops_udp);
#ifdef LUNE_BUILD_SSL
    socket_register_socket_ops(LUNE_SOCKET_SSL, &g_socket_ops_ssl);
    socket_register_socket_ops(LUNE_SOCKET_SSL_LISTEN, &g_socket_ops_ssl_listen);
#endif
    socket_register_socket_ops(LUNE_SOCKET_ICMP, &g_socket_ops_icmp);
    socket_register_socket_ops(LUNE_SOCKET_IGMP, &g_socket_ops_igmp);

    memset(g_socket_cb_sk_stack, 0x00, sizeof(socket_t *) * SOCKET_CB_SK_STACK_SIZE);
    g_socket_cb_sk_stack_offset = 0;

    return 0;

ERR_6:
    lune_assert(!htable_delete_table(s_socket_htable));
    s_socket_htable = NULL;

ERR_5:
    lune_assert(!idtable_delete_table(s_socket_idtable));
    s_socket_idtable = NULL;

ERR_4:
    lune_assert(!idlist_delete_list(s_socket_idlist));
    s_socket_idlist = NULL;

ERR_3:
    (void)lune_delete_mem_pool(g_socket_socket_x_mem_pool);
    g_socket_socket_x_mem_pool = NULL;

ERR_2:
    (void)lune_delete_mem_pool(g_socket_socket_mem_pool);
    g_socket_socket_mem_pool = NULL;

ERR_1:
    return ERR_GET_LAST_ERR();
}

void socket_local_fini(void)
{
    lune_assert(0 == g_socket_cb_sk_stack_offset);

    lune_assert(!htable_delete_table(s_socket_listen_socket_htable));
    s_socket_listen_socket_htable = NULL;

    lune_assert(!htable_delete_table(s_socket_htable));
    s_socket_htable = NULL;

    lune_assert(!idtable_delete_table(s_socket_idtable));
    s_socket_idtable = NULL;

    lune_assert(!idlist_delete_list(s_socket_idlist));
    s_socket_idlist = NULL;

    (void)lune_delete_mem_pool(g_socket_socket_x_mem_pool);
    g_socket_socket_x_mem_pool = NULL;

    (void)lune_delete_mem_pool(g_socket_socket_mem_pool);
    g_socket_socket_mem_pool = NULL;
}

socket_t *__socket_find(socket_t *sk)
{
    return htable_find(sk, s_socket_htable);
}

/*
    caller MUST ensure socket has not been removed
*/
int __socket_remove(socket_t *sk)
{
    int err;

    if (0 == (err = htable_remove(sk, s_socket_htable))) {
        socket_put(sk);
    }

    return err;
}

int __socket_insert(socket_t *sk)
{
    int err;

    if (0 == (err = htable_insert(sk, s_socket_htable, 0))) {
        socket_hold(sk);
    }

    return err;
}

int __socket_is_added(socket_t *sk)
{
    return htable_is_added(sk, s_socket_htable);
}

socket_t *socket_listen_socket_find(socket_t *sk)
{
    return htable_find(sk, s_socket_listen_socket_htable);
}

/*
    caller MUST ensure socket has not been removed
*/
int socket_listen_socket_remove(socket_t *sk)
{
    int err;

    if (0 == (err = htable_remove(sk, s_socket_listen_socket_htable))) {
        socket_put(sk);
    }

    return err;
}

int socket_listen_socket_insert(socket_t *sk)
{
    int err;

    if (0 == (err = htable_insert(sk, s_socket_listen_socket_htable, 0))) {
        socket_hold(sk);
    }

    return err;
}

int socket_is_listen_socket_added(socket_t *sk)
{
    return htable_is_added(sk, s_socket_listen_socket_htable);
}

socket_t *socket_create(lune_socket_type_en type)
{
    socket_t *sk;

    if (LUNE_SOCKET_TCP == type) {
        if (NULL == (sk = lune_mem_pool_alloc(g_socket_socket_x_mem_pool))) {
            goto ERR_1;
        }
    } else {
        if (NULL == (sk = lune_mem_pool_alloc(g_socket_socket_mem_pool))) {
            goto ERR_1;
        }
    }

    if (LUNE_INVALID_ID == (sk->id = idlist_get_new_id(s_socket_idlist))) {
        goto ERR_2;
    }

    if (0 != idtable_insert(sk->id, sk, s_socket_idtable)) {
        goto ERR_3;
    }

    if (0 != (s_socket_ops_array[type].create(sk))) {
        goto ERR_4;
    }

    dlist_init_node(&sk->node);
    sk->ops = &s_socket_ops_array[type];
    sk->rsvd_hdr_len = 0;
    sk->ref_cnt = 0;
    sk->flags = 0;
    sk->type = type;
    socket_hold(sk);

    return sk;

ERR_4:
    lune_assert(!idtable_remove(sk->id, s_socket_idtable));

ERR_3:
    lune_assert(!idlist_del_id(sk->id, s_socket_idlist));

ERR_2:
    if (LUNE_SOCKET_TCP == type) {
        lune_mem_pool_free(g_socket_socket_x_mem_pool, sk);
    } else {
        lune_mem_pool_free(g_socket_socket_mem_pool, sk);
    }

ERR_1:
    return NULL;
}

/*
    caller MUST ensure socket has not been closed
*/
int __socket_close(socket_t *sk)
{
    lune_assert(NULL != sk);

    lune_assert(!idtable_remove(sk->id, s_socket_idtable));
    lune_assert(!idlist_del_id(sk->id, s_socket_idlist));
    socket_put(sk); /* put it for removal from id table */

    return 0;
}

socket_t *socket_get(unsigned int id)
{
    lune_assert(LUNE_INVALID_ID != id);

    return idtable_find(id, s_socket_idtable);
}

unsigned int lune_socket(lune_socket_type_en type)
{
    socket_t *sk;

    SCHED_CHECK_POINT();

    if (unlikely(LUNE_SOCKET_MAX <= type)) {
        ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        return LUNE_INVALID_ID;
    }

    if (unlikely(NULL == s_socket_ops_array[type].create)) {
        /* e.g., add ssl socket without enable_ssl */
        ERR_SET_ERR(LUNE_ERR_NOT_SUPPORTED);
        return LUNE_INVALID_ID;
    }

    if (LUNE_SOCKET_TCP == type) {
        if (NULL == (sk = lune_mem_pool_alloc(g_socket_socket_x_mem_pool))) {
            goto ERR_1;
        }
    } else {
        if (NULL == (sk = lune_mem_pool_alloc(g_socket_socket_mem_pool))) {
            goto ERR_1;
        }
    }

    if (LUNE_INVALID_ID == (sk->id = idlist_get_new_id(s_socket_idlist))) {
        goto ERR_2;
    }

    if (0 != idtable_insert(sk->id, sk, s_socket_idtable)) {
        goto ERR_3;
    }

    /* create() not NULL*/
    if (0 != (s_socket_ops_array[type].create(sk))) {
        goto ERR_4;
    }

    dlist_init_node(&sk->node);
    sk->ops = &s_socket_ops_array[type];
    sk->rsvd_hdr_len = 0;
    sk->ref_cnt = 0;
    sk->flags = 0;
    SOCKET_CLOSE_SET_OFF(sk);
    sk->type = type;
    socket_hold(sk); /* hold it for insertion into id table */

    return sk->id;

ERR_4:
    lune_assert(!idtable_remove(sk->id, s_socket_idtable));

ERR_3:
    lune_assert(!idlist_del_id(sk->id, s_socket_idlist));

ERR_2:
    if (LUNE_SOCKET_TCP == type) {
        lune_mem_pool_free(g_socket_socket_x_mem_pool, sk);
    } else {
        lune_mem_pool_free(g_socket_socket_mem_pool, sk);
    }

ERR_1:
    return LUNE_INVALID_ID;
}

int lune_bind(unsigned int id, void *arg, unsigned int arg_len)
{
    socket_t *sk;

    SCHED_CHECK_POINT();

    if (unlikely(LUNE_INVALID_ID == id || NULL == arg)) {
        return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
    }

    if (NULL == (sk = socket_get(id))) {
        return ERR_SET_ERR(LUNE_ERR_ID_NOT_FOUND);
    }

    if (unlikely(SOCKET_CLOSE_ON(sk))) {
        lune_log(LUNE_INFO, "socket %d has already been closed", id);
        return ERR_SET_ERR(LUNE_ERR_ALREADY_CLOSED);
    }

    /* bind() not NULL*/
    return sk->ops->bind(sk, arg, arg_len);
}

int lune_connect(unsigned int id, void *arg, unsigned int arg_len)
{
    socket_t *sk;

    SCHED_CHECK_POINT();

    if (unlikely(LUNE_INVALID_ID == id || NULL == arg)) {
        return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
    }

    if (NULL == (sk = socket_get(id))) {
        return ERR_SET_ERR(LUNE_ERR_ID_NOT_FOUND);
    }

    if (unlikely(SOCKET_CLOSE_ON(sk))) {
        lune_log(LUNE_INFO, "socket %d has already been closed", id);
        return ERR_SET_ERR(LUNE_ERR_ALREADY_CLOSED);
    }

    if (unlikely(NULL == sk->ops->connect)) {
        return ERR_SET_ERR(LUNE_ERR_NOT_SUPPORTED);
    }

    return sk->ops->connect(sk, arg, arg_len);
}

int lune_listen(unsigned int id, unsigned int backlog)
{
    socket_t *sk;

    SCHED_CHECK_POINT();

    if (unlikely(LUNE_INVALID_ID == id)) {
        return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
    }

    if (NULL == (sk = socket_get(id))) {
        return ERR_SET_ERR(LUNE_ERR_ID_NOT_FOUND);
    }

    lune_assert(!SOCKET_CLOSE_ON(sk));

    if (unlikely(NULL == sk->ops->listen)) {
        return ERR_SET_ERR(LUNE_ERR_NOT_SUPPORTED);
    }

    return sk->ops->listen(sk, backlog);
}

int lune_send(unsigned int id, const unsigned char *buf, unsigned int len)
{
    socket_t *sk;

    SCHED_CHECK_POINT();

    if (unlikely(LUNE_INVALID_ID == id || NULL == buf || 0 == len)) {
        return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
    }

    if (NULL == (sk = socket_get(id))) {
        return ERR_SET_ERR(LUNE_ERR_ID_NOT_FOUND);
    }

    if (unlikely(SOCKET_CLOSE_ON(sk))) {
        lune_log(LUNE_INFO, "socket %d has already been closed", id);
        return ERR_SET_ERR(LUNE_ERR_ALREADY_CLOSED);
    }

    if (unlikely(NULL == sk->ops->send)) {
        return ERR_SET_ERR(LUNE_ERR_NOT_SUPPORTED);
    }

    return sk->ops->send(sk, buf, len);
}

int lune_send_pkts(unsigned int id,
    lune_socket_send_pkt_t *pkts, unsigned int pkt_num, unsigned int mode)
{
    unsigned int i;
    socket_t *sk;

    SCHED_CHECK_POINT();

    if (unlikely(LUNE_INVALID_ID == id
        || NULL == pkts
        || 0 == pkt_num
        || mode < LUNE_SOCKET_SEND_PKTS_DEFAULT
        || mode > LUNE_SOCKET_SEND_PKTS_UNCHANGED)) {
        return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
    }

    for (i = 0; i < pkt_num; i++) {
        if (0 == pkts[i].len) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }
    }

    if (NULL == (sk = socket_get(id))) {
        return ERR_SET_ERR(LUNE_ERR_ID_NOT_FOUND);
    }

    if (unlikely(SOCKET_CLOSE_ON(sk))) {
        lune_log(LUNE_INFO, "socket %d has already been closed", id);
        return ERR_SET_ERR(LUNE_ERR_ALREADY_CLOSED);
    }

    if (1 == pkt_num && likely(NULL != sk->ops->send)) {
        int err;

        if (0 != (err = sk->ops->send(sk, pkts->buf, pkts->len))) {
            return err;
        }

        return 1;
    }

    if (unlikely(NULL == sk->ops->send_pkts)) {
        return ERR_SET_ERR(LUNE_ERR_NOT_SUPPORTED);
    }

    return sk->ops->send_pkts(sk, pkts, pkt_num, mode);
}

int lune_send_in_cb(const unsigned char *buf, unsigned int len)
{
    socket_t *sk;

    if (unlikely(NULL == buf || 0 == len)) {
        return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
    }

    sk = SOCKET_GET_CB_SK();
    if (unlikely(NULL == sk)) {
        /* not supported either by protocol or by specific callback function */
        return ERR_SET_ERR(LUNE_ERR_NOT_SUPPORTED);
    }

    if (unlikely(SOCKET_CLOSE_ON(sk))) {
        lune_log(LUNE_INFO, "socket %d has already been closed", sk->id);
        return ERR_SET_ERR(LUNE_ERR_ALREADY_CLOSED);
    }

    if (unlikely(NULL == sk->ops->send)) {
        return ERR_SET_ERR(LUNE_ERR_NOT_SUPPORTED);
    }

    return sk->ops->send(sk, buf, len);
}

int lune_send_pkts_in_cb(lune_socket_send_pkt_t *pkts,
    unsigned int pkt_num, unsigned int mode)
{
    unsigned int i;
    socket_t *sk;

    if (unlikely(NULL == pkts
        || 0 == pkt_num
        || mode < LUNE_SOCKET_SEND_PKTS_DEFAULT
        || mode > LUNE_SOCKET_SEND_PKTS_UNCHANGED)) {
        return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
    }

    for (i = 0; i < pkt_num; i++) {
        if (0 == pkts[i].len) {
            return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        }
    }

    sk = SOCKET_GET_CB_SK();
    if (unlikely(NULL == sk)) {
        /* not supported either by protocol or by specific callback function */
        return ERR_SET_ERR(LUNE_ERR_NOT_SUPPORTED);
    }

    if (unlikely(SOCKET_CLOSE_ON(sk))) {
        lune_log(LUNE_INFO, "socket %d has already been closed", sk->id);
        return ERR_SET_ERR(LUNE_ERR_ALREADY_CLOSED);
    }

    if (1 == pkt_num && likely(NULL != sk->ops->send)) {
        return sk->ops->send(sk, pkts->buf, pkts->len);
    }

    if (unlikely(NULL == sk->ops->send_pkts)) {
        return ERR_SET_ERR(LUNE_ERR_NOT_SUPPORTED);
    }

    return sk->ops->send_pkts(sk, pkts, pkt_num, mode);
}

int lune_sendto(unsigned int id, const unsigned char *buf, unsigned int len,
    const void *dst_addr, unsigned int dst_addr_len, const void *arg, unsigned int arg_len)
{
    socket_t *sk;

    SCHED_CHECK_POINT();

    if (unlikely(LUNE_INVALID_ID == id 
        || (NULL == buf && 0 != len)
        || (NULL != buf && 0 == len)
        || NULL == dst_addr || 0 == dst_addr_len)) {
        return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
    }

    if (NULL == (sk = socket_get(id))) {
        return ERR_SET_ERR(LUNE_ERR_ID_NOT_FOUND);
    }

    if (unlikely(SOCKET_CLOSE_ON(sk))) {
        lune_log(LUNE_INFO, "socket %d has already been closed", id);
        return ERR_SET_ERR(LUNE_ERR_ALREADY_CLOSED);
    }

    if (unlikely(NULL == sk->ops->sendto)) {
        return ERR_SET_ERR(LUNE_ERR_NOT_SUPPORTED);
    }

    return sk->ops->sendto(sk, buf, len, dst_addr, dst_addr_len, arg, arg_len);
}

int lune_sendto_in_cb(const unsigned char *buf, unsigned int len,
    void *dst_addr, unsigned int dst_addr_len, void *arg, unsigned int arg_len)
{
    socket_t *sk;

    if (unlikely(NULL == buf || 0 == len 
        || NULL == dst_addr || 0 == dst_addr_len)) {
        return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
    }

    sk = SOCKET_GET_CB_SK();
    if (unlikely(NULL == sk)) {
        /* not supported either by protocol or by specific callback function */
        return ERR_SET_ERR(LUNE_ERR_NOT_SUPPORTED);
    }

    if (unlikely(SOCKET_CLOSE_ON(sk))) {
        lune_log(LUNE_INFO, "socket %d has already been closed", sk->id);
        return ERR_SET_ERR(LUNE_ERR_ALREADY_CLOSED);
    }

    if (unlikely(NULL == sk->ops->sendto)) {
        return ERR_SET_ERR(LUNE_ERR_NOT_SUPPORTED);
    }

    return sk->ops->sendto(sk, buf, len, dst_addr, dst_addr_len, arg, arg_len);
}

int lune_close(unsigned int id)
{
    socket_t *sk;
    int err;

    SCHED_CHECK_POINT();

    if (unlikely(LUNE_INVALID_ID == id)) {
        return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
    }

    if (NULL == (sk = socket_get(id))) {
        return ERR_SET_ERR(LUNE_ERR_ID_NOT_FOUND);
    }

    if (unlikely(SOCKET_CLOSE_ON(sk))) {
        lune_log(LUNE_INFO, "socket %d has already been closed", id);
        return ERR_SET_ERR(LUNE_ERR_ALREADY_CLOSED);
    }

    SOCKET_CLOSE_SET_ON(sk);

    /* close() not NULL*/
    if (0 != (err = sk->ops->close(sk))) {
        /* remain open if it fails to close */
        SOCKET_CLOSE_SET_OFF(sk);
        return err;
    }

    return socket_close(sk);
}

int lune_close_in_cb(void)
{
    int err;
    socket_t *sk = SOCKET_GET_CB_SK();

    if (unlikely(NULL == sk)) {
        /* not supported either by protocol or by specific callback function */
        return ERR_SET_ERR(LUNE_ERR_NOT_SUPPORTED);
    }

    if (unlikely(SOCKET_CLOSE_ON(sk))) {
        lune_log(LUNE_INFO, "socket %d has already been closed", sk->id);
        return ERR_SET_ERR(LUNE_ERR_ALREADY_CLOSED);
    }

    SOCKET_CLOSE_SET_ON(sk);

    /* close() not NULL*/
    if (0 != (err = sk->ops->close(sk))) {
        /* remain open if it fails to close */
        SOCKET_CLOSE_SET_OFF(sk);
        return err;
    }

    return socket_close(sk);
}

int lune_get_socket_opt(unsigned int id,
    lune_socket_opt_en opt, unsigned char *opt_val, unsigned int opt_len)
{
    socket_t *sk;

    SCHED_CHECK_POINT();

    if (unlikely(LUNE_INVALID_ID == id || NULL == opt_val || 0 == opt_len)) {
        return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
    }

    if (NULL == (sk = socket_get(id))) {
        return ERR_SET_ERR(LUNE_ERR_ID_NOT_FOUND);
    }

    if (unlikely(SOCKET_CLOSE_ON(sk))) {
        lune_log(LUNE_INFO, "socket %d has already been closed", id);
        return ERR_SET_ERR(LUNE_ERR_ALREADY_CLOSED);
    }

    if (unlikely(NULL == sk->ops->get_opt)) {
        return ERR_SET_ERR(LUNE_ERR_NOT_SUPPORTED);
    }

    return sk->ops->get_opt(sk, opt, opt_val, opt_len);
}

int lune_get_socket_opt_in_cb(lune_socket_opt_en opt,
    unsigned char *opt_val, unsigned int opt_len)
{
    socket_t *sk;

    if (unlikely(NULL == opt_val || 0 == opt_len)) {
        return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
    }

    sk = SOCKET_GET_CB_SK();
    if (unlikely(NULL == sk)) {
        /* not supported either by protocol or by specific callback function */
        return ERR_SET_ERR(LUNE_ERR_NOT_SUPPORTED);
    }

    if (unlikely(SOCKET_CLOSE_ON(sk))) {
        lune_log(LUNE_INFO, "socket %d has already been closed", sk->id);
        return ERR_SET_ERR(LUNE_ERR_ALREADY_CLOSED);
    }

    if (unlikely(NULL == sk->ops->get_opt)) {
        return ERR_SET_ERR(LUNE_ERR_NOT_SUPPORTED);
    }

    return sk->ops->get_opt(sk, opt, opt_val, opt_len);
}

int lune_set_socket_opt(unsigned int id,
    lune_socket_opt_en opt, const unsigned char *opt_val, unsigned int opt_len)
{
    socket_t *sk;

    SCHED_CHECK_POINT();

    if (unlikely(LUNE_INVALID_ID == id)) {
        return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
    }

    if (NULL == (sk = socket_get(id))) {
        return ERR_SET_ERR(LUNE_ERR_ID_NOT_FOUND);
    }

    if (unlikely(SOCKET_CLOSE_ON(sk))) {
        lune_log(LUNE_INFO, "socket %d has already been closed", id);
        return ERR_SET_ERR(LUNE_ERR_ALREADY_CLOSED);
    }

    if (unlikely(NULL == sk->ops->set_opt)) {
        return ERR_SET_ERR(LUNE_ERR_NOT_SUPPORTED);
    }

    return sk->ops->set_opt(sk, opt, opt_val, opt_len);
}

int lune_set_socket_opt_in_cb(lune_socket_opt_en opt,
    const unsigned char *opt_val, unsigned int opt_len)
{
    socket_t *sk = SOCKET_GET_CB_SK();

    if (unlikely(NULL == sk)) {
        /* not supported either by protocol or by specific callback function */
        return ERR_SET_ERR(LUNE_ERR_NOT_SUPPORTED);
    }

    if (unlikely(SOCKET_CLOSE_ON(sk))) {
        lune_log(LUNE_INFO, "socket %d has already been closed", sk->id);
        return ERR_SET_ERR(LUNE_ERR_ALREADY_CLOSED);
    }

    if (unlikely(NULL == sk->ops->set_opt)) {
        return ERR_SET_ERR(LUNE_ERR_NOT_SUPPORTED);
    }

    return sk->ops->set_opt(sk, opt, opt_val, opt_len);
}
