/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2024 Lune Reseau, Inc.
 */

#include "lune/assert.h"
#include "lune/common.h"
#include "lune/err.h"
#include "lune/list.h"
#include "lune/log.h"
#include "lune/mem.h"
#include "lune/os/linux.h"

#include "err/err.h"
#include "lib/htable.h"

#define HTABLE_IS_VALID_SIZE(s)     IS_POW2_NUM(s)

/*
    generic single-thread hash table
*/

#pragma pack(8)
typedef struct _bucket {
    dlist_head_t head;
    unsigned int elem_cnt;
} bucket_t;

typedef struct _htable {
    htable_hash_func_t hash;
    htable_compare_func_t compare;
    /*
        free() will only be called while deleting entire hash table
    */
    htable_free_func_t free;
    unsigned int offset;
    unsigned int size;
    bucket_t *bucket;
    char name[LUNE_MAX_SHORT_NAME_BUF_LEN];
    struct {
        unsigned int elem_cnt;
    } stats;
#define HTABLE_FLAG_FAST_CREATION           0x00000001
#define HTABLE_IS_FAST_CREATION(htable)     ((htable)->flags & HTABLE_FLAG_FAST_CREATION)
#define HTABLE_SET_FAST_CREATION(htable)    \
    do { (htable)->flags = ((htable)->flags | (HTABLE_FLAG_FAST_CREATION)); } while (0)
#define HTABLE_CLEAR_FAST_CREATION(htable)  \
    do { (htable)->flags = ((htable)->flags & (~HTABLE_FLAG_FAST_CREATION)); } while (0)
    unsigned int flags;
    unsigned long long init_bit_map[0];
} htable_t;
#pragma pack()

void *htable_create_table(const char *name,
    htable_hash_func_t hash,
    htable_compare_func_t compare,
    htable_free_func_t free,
    unsigned int offset,
    unsigned int size,
    unsigned int fast_creation)
{
    htable_t *htable;
    unsigned int i;

    if (NULL == name) {
        ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        goto ERR_1;
    }

    if (strlen(name) > LUNE_MAX_SHORT_NAME_LEN) {
        ERR_SET_ERR(LUNE_ERR_NAME_TOO_LONG);
        goto ERR_1;
    }

    if (NULL == hash || NULL == compare || !HTABLE_IS_VALID_SIZE(size)) {
        ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        goto ERR_1;
    }

    if (fast_creation) {
        if (NULL == (htable = lune_malloc(sizeof(htable_t)
            + sizeof(unsigned long long) * ((size >> 6) > 0 ? (size >> 6) : 1)))) {
            goto ERR_1;
        }
    } else {
        if (NULL == (htable = lune_malloc(sizeof(htable_t)))) {
            goto ERR_1;
        }
    }

    htable->hash = hash;
    htable->compare = compare;
    htable->free = free;
    htable->offset = offset;
    htable->size = size;
    strcpy(htable->name, name);
    htable->stats.elem_cnt = 0;
    htable->flags = 0;
    if (NULL == (htable->bucket = lune_malloc_x(sizeof(bucket_t) * htable->size))) {
        goto ERR_2;
    }

    if (fast_creation) {
        unsigned int init_bit_map_size = (size >> 6) > 0 ? (size >> 6) : 1;
        HTABLE_SET_FAST_CREATION(htable);
        for (i = 0; i < init_bit_map_size; i++) {
            htable->init_bit_map[i] = 0;
        }
    } else {
        HTABLE_CLEAR_FAST_CREATION(htable);
        for (i = 0; i < htable->size; i++) {
            dlist_init_head(&htable->bucket[i].head);
            htable->bucket[i].elem_cnt = 0;
        }
    }

    return htable;

ERR_2:
    lune_free(htable);

ERR_1:
    return NULL;
}

int htable_delete_table(void *htable)
{
    htable_t *ht;
    unsigned int i, j, k;
    dlist_node_t *n, *n2;
    void *elem;

    if (NULL == htable) {
        return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
    }

    ht = (htable_t *)htable;
    if (ht->stats.elem_cnt > 0) {
        lune_log(LUNE_INFO, "%d elements still in hash table %s while deleting it", 
            ht->stats.elem_cnt, ht->name);
        if (HTABLE_IS_FAST_CREATION(ht)) {
            unsigned int init_bit_map_size = (ht->size >> 6) > 0 ? (ht->size >> 6) : 1;
            for (i = 0; i < init_bit_map_size; i++) {
                if (ht->init_bit_map[i] != 0) {
                    for (j = 0; j < 64; j++) {
                        if (ht->init_bit_map[i] & (1 << j)) {
                            k = (i << 6) + j;
                            dlist_for_each_safe(n, n2, &ht->bucket[k].head) {
                                dlist_del_init(n);
                                if (NULL != ht->free) {
                                    elem = ((char *)n) - ht->offset;
                                    ht->free(elem);
                                    ht->stats.elem_cnt--;
                                }
                            }
                        }
                    }
                }
            }
        } else {
            for (i = 0; i < ht->size; i++) {
                dlist_for_each_safe(n, n2, &ht->bucket[i].head) {
                    dlist_del_init(n);
                    if (NULL != ht->free) {
                        elem = ((char *)n) - ht->offset;
                        ht->free(elem);
                        ht->stats.elem_cnt--;
                    }
                }
            }
        }

        lune_assert(0 == ht->stats.elem_cnt);
    }

    lune_free_x(ht->bucket);
    lune_free(ht);

    return 0;
}

int htable_insert(void *elem, void *htable, unsigned int skip_search)
{
    htable_t *ht;
    unsigned int hash;
    dlist_node_t *n;

    if (unlikely(NULL == htable || NULL == elem)) {
        return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
    }

    ht = (htable_t *)htable;
    hash = ht->hash(elem);
    lune_assert(hash < ht->size);

    if (HTABLE_IS_FAST_CREATION(ht)
        && !(ht->init_bit_map[hash >> 6] & ((unsigned long long)1 << (hash % 64)))) {
        dlist_init_head(&ht->bucket[hash].head);
        ht->bucket[hash].elem_cnt = 0;
        ht->init_bit_map[hash >> 6] |= ((unsigned long long)1 << (hash % 64));
    } else if (!skip_search) {
        dlist_for_each(n, &ht->bucket[hash].head) {
            if (!ht->compare(((char *)n) - ht->offset, elem)) {
                return ERR_SET_ERR(LUNE_ERR_ALREADY_EXIST);
            }
        }
    }

    dlist_add_tail((dlist_head_t *)(((char *)elem) + ht->offset), &ht->bucket[hash].head);
    ht->bucket[hash].elem_cnt++;
    ht->stats.elem_cnt++;

    return 0;
}

void *htable_find(void *elem, void *htable)
{
    htable_t *ht;
    unsigned int hash;
    dlist_node_t *n, *n2;

    if (unlikely(NULL == htable || NULL == elem)) {
        ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        return NULL;
    }

    ht = (htable_t *)htable;
    hash = ht->hash(elem);
    lune_assert(hash < ht->size);

    if (HTABLE_IS_FAST_CREATION(ht)
        && !(ht->init_bit_map[hash >> 6] & ((unsigned long long)1 << (hash % 64)))) {
        return NULL;
    }

    dlist_for_each_safe(n, n2, &ht->bucket[hash].head) {
        if (!ht->compare(((char *)n) - ht->offset, elem)) {
            return (void *)(((char *)n) - ht->offset);
        }
    }

    return NULL;
}

int htable_remove(void *elem, void *htable)
{
    htable_t *ht;
    unsigned int hash;
    dlist_head_t *n;

    if (unlikely(NULL == htable || NULL == elem)) {
        return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
    }

    ht = (htable_t *)htable;

    n = (dlist_head_t *)(((char *)elem) + ht->offset);
    if (unlikely(dlist_is_empty(n))) {
        return ERR_SET_ERR(LUNE_ERR_NOT_EXIST);
    }

    dlist_del_init(n);

    hash = ht->hash(elem);
    lune_assert(hash < ht->size);

    ht->bucket[hash].elem_cnt--;
    ht->stats.elem_cnt--;

    return 0;
}

int htable_is_added(void *elem, void *htable)
{
    dlist_node_t *n;

    if (unlikely(NULL == htable || NULL == elem)) {
        return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
    }

    n = (dlist_node_t *)(((char *)elem) + ((htable_t *)htable)->offset);
    return !dlist_is_empty(n);    
}

/*
    generic thread-safe hash table
*/

typedef struct _bucket_mt {
    dlist_head_t head;
    pthread_spinlock_t lock;
    unsigned int elem_cnt;
} bucket_mt_t;

typedef struct _htable_mt {
    htable_hash_func_t hash;
    htable_compare_func_t compare;
    htable_hold_func_t hold;
    htable_put_func_t put;
    unsigned int offset;
    unsigned int size;
    bucket_mt_t *bucket;
    char name[LUNE_MAX_SHORT_NAME_BUF_LEN];
    struct {
        unsigned int elem_cnt;
    } stats;
} htable_mt_t;

void *htable_create_table_mt(const char *name,
    htable_hash_func_t hash,
    htable_compare_func_t compare,
    htable_hold_func_t hold,
    htable_put_func_t put,
    unsigned int offset,
    unsigned int size)
{
    htable_mt_t *htable;
    unsigned int i, j;

    if (NULL == name) {
        ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        return NULL;
    }

    if (strlen(name) > LUNE_MAX_SHORT_NAME_LEN) {
        ERR_SET_ERR(LUNE_ERR_NAME_TOO_LONG);
        return NULL;
    }

    if (NULL == hash || NULL == compare || NULL == hold || NULL == put || !HTABLE_IS_VALID_SIZE(size)) {
        ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        return NULL;
    }

    if (NULL == (htable = lune_malloc_mt(sizeof(htable_mt_t)))) {
        goto ERR_1;
    }

    htable->hash = hash;
    htable->compare = compare;
    htable->hold = hold;
    htable->put = put;
    htable->offset = offset;
    htable->size = size;
    strcpy(htable->name, name);
    htable->stats.elem_cnt = 0;

    if (NULL == (htable->bucket = lune_malloc_mt(sizeof(bucket_mt_t) * htable->size))) {
        goto ERR_2;
    }

    for (i = 0; i < htable->size; i++) {
        dlist_init_head(&htable->bucket[i].head);
        if (0 != pthread_spin_init(&htable->bucket[i].lock, PTHREAD_PROCESS_PRIVATE)) {
            ERR_SET_ERR(LUNE_ERR_SYS_ERR);
            goto ERR_3;
        }
        htable->bucket[i].elem_cnt = 0;
    }

    return htable;

ERR_3:
    for (j = 0; j < i; j++) {
        lune_assert(!pthread_spin_destroy((&htable->bucket[j].lock)));
    }

ERR_2:
    lune_free_mt(htable);

ERR_1:
    return NULL;
}

int htable_delete_table_mt(void *htable)
{
    htable_mt_t *ht;
    unsigned int i;
    dlist_node_t *n, *n2;
    void *elem;

    if (NULL == htable) {
        return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
    }

    ht = (htable_mt_t *)htable;
    if (ht->stats.elem_cnt > 0) {
        lune_log(LUNE_INFO, "%d elements still in hash table %s while deleting it", 
            ht->stats.elem_cnt, ht->name);
        for (i = 0; i < ht->size; i++) {
            pthread_spin_lock(&ht->bucket[i].lock);
            dlist_for_each_safe(n, n2, &ht->bucket[i].head) {
                dlist_del_init(n);
                elem = ((char *)n) - ht->offset;
                ht->put(elem);
                ht->stats.elem_cnt--;
            }
            pthread_spin_unlock(&ht->bucket[i].lock);
            lune_assert(!pthread_spin_destroy(&ht->bucket[i].lock));
        }
        lune_assert(0 == ht->stats.elem_cnt);
    }

    lune_free_mt(ht->bucket);
    lune_free_mt(ht);

    return 0;
}

int htable_insert_mt(void *elem, void *htable)
{
    htable_mt_t *ht;
    unsigned int hash;
    dlist_node_t *n, *n2;

    if (NULL == htable || NULL == elem) {
        return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
    }

    ht = (htable_mt_t *)htable;
    hash = ht->hash(elem);
    lune_assert(hash < ht->size);

    pthread_spin_lock(&ht->bucket[hash].lock);
    dlist_for_each_safe(n, n2, &ht->bucket[hash].head) {
        if (!ht->compare(((char *)n) - ht->offset, elem)) {
            pthread_spin_unlock(&ht->bucket[hash].lock);
            return ERR_SET_ERR(LUNE_ERR_ALREADY_EXIST);
        }
    }

    dlist_add_tail((dlist_head_t *)(((char *)elem) + ht->offset), &ht->bucket[hash].head);
    ht->bucket[hash].elem_cnt++;
    ht->stats.elem_cnt++;
    ht->hold(elem);
    pthread_spin_unlock(&ht->bucket[hash].lock);

    return 0;
}

void *htable_find_mt(void *elem, void *htable)
{
    htable_mt_t *ht;
    unsigned int hash;
    dlist_node_t *n, *n2;

    if (NULL == htable || NULL == elem) {
        ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        return NULL;
    }

    ht = (htable_mt_t *)htable;
    hash = ht->hash(elem);
    lune_assert(hash < ht->size);

    pthread_spin_lock(&ht->bucket[hash].lock);
    dlist_for_each_safe(n, n2, &ht->bucket[hash].head) {
        if (!ht->compare(((char *)n) - ht->offset, elem)) {
            ht->hold(((char *)n) - ht->offset);
            pthread_spin_unlock(&ht->bucket[hash].lock);
            return (void *)(((char *)n) - ht->offset);
        }
    }

    pthread_spin_unlock(&ht->bucket[hash].lock);
    return NULL;
}

int htable_find_done_mt(void *elem, void *htable)
{
    htable_mt_t *ht = (htable_mt_t *)htable;

    if (NULL == ht || NULL == elem) {
        return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
    }

    ht->put(elem);
    return 0;
}

int htable_remove_mt(void *elem, void *htable)
{
    htable_mt_t *ht;
    unsigned int hash;
    dlist_head_t *n;

    if (NULL == htable || NULL == elem) {
        return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
    }

    ht = (htable_mt_t *)htable;
    hash = ht->hash(elem);
    lune_assert(hash < ht->size);

    pthread_spin_lock(&ht->bucket[hash].lock);
    n = (dlist_head_t *)(((char *)elem) + ht->offset);
    if (dlist_is_empty(n)) {
        pthread_spin_unlock(&ht->bucket[hash].lock);
        return ERR_SET_ERR(LUNE_ERR_NOT_EXIST);
    }

    dlist_del_init(n);

    ht->bucket[hash].elem_cnt--;
    ht->stats.elem_cnt--;
    ht->put(elem);

    pthread_spin_unlock(&ht->bucket[hash].lock);

    return 0;
}

int htable_local_init(void)
{
    return 0;
}

void htable_local_fini(void)
{
    return;
}
