/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2024 Lune Reseau, Inc.
 */

#ifndef __LUNE_LIST_H__
#define __LUNE_LIST_H__

#include "lune/os/linux.h"

#ifdef __cplusplus
extern "C" {
#endif

#define lune_container_of(ptr, type, member) ({                 \
    typeof(((type *)0)->member) *_mp = (ptr);                   \
    (type *)((char *)_mp - offsetof(type,member)); })

/*
    doubly linked list
*/
typedef struct _dlist_node {
    struct _dlist_node *next, *prev;
} dlist_node_t;

typedef dlist_node_t dlist_head_t;

#define DLIST_HEAD_INIT(name)   { &(name), &(name) }

#define dlist_init_node(node)   dlist_init_head(node)

static inline void dlist_init_head(dlist_head_t *head)
{
    head->next = head;
    head->prev = head;
}

static inline int dlist_one_node_only(dlist_head_t *head)
{
    if (head->next == head) {
        return 0;
    }

    return head->next->next == head ? 1 : 0;
}

static inline int dlist_is_empty(const dlist_head_t *head)
{
    return head->next == head;
}

static inline int dlist_node_is_added(const dlist_node_t *node)
{
    return (!(node->next == node));
}

static inline int dlist_node_is_last(dlist_node_t *node, dlist_head_t *head)
{
    return (node->next == head);
}

static inline void dlist_add(dlist_node_t *node,
    dlist_node_t *prev,
    dlist_node_t *next)
{
    next->prev = node;
    node->next = next;
    node->prev = prev;
    prev->next = node;
}

static inline void dlist_add_head(dlist_node_t *node, dlist_head_t *head)
{
    dlist_add(node, head, head->next);
}

static inline void dlist_add_tail(dlist_node_t *node, dlist_head_t *head)
{
    dlist_add(node, head->prev, head);
}

static inline void dlist_add_prev(dlist_node_t *node, dlist_node_t *next)
{
    dlist_add(node, next->prev, next);
}

static inline void dlist_add_next(dlist_node_t *node, dlist_node_t *prev)
{
    dlist_add(node, prev, prev->next);
}

static inline void dlist_replace(dlist_node_t *new_node, dlist_node_t *old_node)
{
    new_node->next = old_node->next;
    new_node->next->prev = new_node;
    new_node->prev = old_node->prev;
    new_node->prev->next = new_node;
}

static inline void __dlist_del(dlist_node_t *prev, dlist_node_t *next)
{
    next->prev = prev;
    prev->next = next;
}

static inline void dlist_del(dlist_node_t *node)
{
    __dlist_del(node->prev, node->next);
#ifdef LUNE_DEBUG
    node->next = NULL;
    node->prev = NULL;
#endif
}

/*
    for all move-list-related functions, caller MUST ensure list to be 
    moved is NOT empty
*/
static inline void dlist_move_list(dlist_head_t *old_head, dlist_head_t *new_head)
{
    new_head->next = old_head->next;
    new_head->next->prev = new_head;
    new_head->prev = old_head->prev;
    new_head->prev->next = new_head;
}

static inline void dlist_move_list_init(dlist_head_t *old_head, dlist_head_t *new_head)
{
    dlist_move_list(old_head, new_head);
    dlist_init_head(old_head);
}

static inline void dlist_move_list_tail(dlist_head_t *old_head, dlist_head_t *new_head)
{
    new_head->prev->next = old_head->next;
    new_head->prev->next->prev = new_head->prev;
    new_head->prev = old_head->prev;
    new_head->prev->next = new_head;
}

static inline void dlist_move_list_tail_init(dlist_head_t *old_head, dlist_head_t *new_head)
{
    dlist_move_list_tail(old_head, new_head);
    dlist_init_head(old_head);
}

static inline void dlist_replace_node(dlist_node_t *old_node, dlist_node_t *new_node)
{
    new_node->next = old_node->next;
    new_node->next->prev = new_node;
    new_node->prev = old_node->prev;
    new_node->prev->next = new_node;
}

static inline void dlist_del_init(dlist_node_t *node)
{
    dlist_del(node);
    dlist_init_node(node);
}

#define dlist_node(ptr, type, member)                           lune_container_of(ptr, type, member)

/* return node or head */
#define dlist_prev(pos, member)                                 \
    dlist_node((pos)->member.prev, typeof(*(pos)), member)

/* return node or head */
#define dlist_next(pos, member)                                 \
    dlist_node((pos)->member.next, typeof(*(pos)), member)

#define dlist_first(head, type, member)                         dlist_node((head)->next, type, member)

#define dlist_last(head, type, member)                          dlist_node((head)->prev, type, member)

/* return node, caller MUST guarantee list not empty */
#define dlist_prev_node(pos, head, member, repeat)                      \
    (((pos)->member.prev == head)                                       \
        ? ((repeat) ? dlist_last(head, typeof(*pos), member) : NULL)    \
        : dlist_prev(pos, member))

/* return node, caller MUST guarantee list not empty */
#define dlist_next_node(pos, head, member, repeat)                      \
    (((pos)->member.next == head)                                       \
        ? ((repeat) ? dlist_first(head, typeof(*pos), member) : NULL)   \
        : dlist_next(pos, member))

#define dlist_for_each(pos, head)                               \
    for (pos = (head)->next; pos != (head); pos = pos->next)

#define dlist_for_each_safe(pos, n, head)                       \
    for (pos = (head)->next, n = pos->next; pos != (head); pos = n, n = pos->next)

#define dlist_for_each_node(pos, head, member)                  \
    for (pos = dlist_first(head, typeof(*pos), member);         \
         &pos->member != (head);                                \
         pos = dlist_next(pos, member))

#define dlist_for_each_node_2(pos, head, type, member)          \
    for (pos = dlist_first(head, type, member);                 \
         &((type *)pos)->member != (head);                      \
         pos = dlist_next((type *)pos, member))

#define dlist_for_each_node_safe(pos, n, head, member)          \
    for (pos = dlist_first(head, typeof(*pos), member),         \
        n = dlist_next(pos, member);                            \
         &pos->member != (head);                                \
         pos = n, n = dlist_next(n, member))

#define dlist_for_each_node_safe_2(pos, n, head, type, member)  \
    for (pos = dlist_first(head, type, member),                 \
        n = dlist_next((type *)pos, member);                    \
         &((type *)pos)->member != (head);                      \
         pos = n, n = dlist_next((type *)pos, member))

#define dlist_for_each_node_reverse(pos, head, member)          \
    for (pos = dlist_last(head, typeof(*pos), member);     \
         &pos->member != (head);                                \
         pos = dlist_prev(pos, member))

#define dlist_for_each_node_reverse_safe(pos, n, head, member)  \
    for (pos = dlist_last(head, typeof(*pos), member),     \
        n = dlist_prev(pos, member);                       \
         &pos->member != (head);                                \
         pos = n, n = dlist_prev(n, member))

#ifdef __cplusplus
}
#endif

#endif