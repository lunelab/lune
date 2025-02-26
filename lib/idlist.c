/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2024 Lune Reseau, Inc.
 */

#include "lune/assert.h"
#include "lune/common.h"
#include "lune/err.h"
#include "lune/id.h"
#include "lune/list.h"
#include "lune/log.h"
#include "lune/os/linux.h"

#include "err/err.h"
#include "kernel/sched.h"
#include "lib/common.h"
#include "lib/idlist.h"
#include "log/log.h"
#include "mem/mem.h"

#define IDLIST_MIN_NUM_OF_FREE_ID           (128)
#define IDLIST_NUM_OF_ID_PER_BLOCK_IN_BIT   (10)
#define IDLIST_NUM_OF_ID_PER_BLOCK          (1 << IDLIST_NUM_OF_ID_PER_BLOCK_IN_BIT)
#define IDLIST_NUM_OF_BLOCK_IN_BIT          \
    (ID_MAX_NUM_OF_ID_IN_BIT - IDLIST_NUM_OF_ID_PER_BLOCK_IN_BIT)
#define IDLIST_NUM_OF_BLOCK                 (1 << IDLIST_NUM_OF_BLOCK_IN_BIT)
#define IDLIST_ID_PER_BLOCK_MASK            (IDLIST_NUM_OF_ID_PER_BLOCK - 1)

#define IDLIST_MAX_ID                       ((unsigned int)(1 << ID_MAX_NUM_OF_ID_IN_BIT))

typedef struct _idlist {
    dlist_node_t node;
    dlist_head_t free_list;
    dlist_head_t inuse_list;
    unsigned int total_id_cnt;
    unsigned int inuse_id_cnt;
    void *id_pool;
    char name[LUNE_MAX_SHORT_NAME_BUF_LEN];
    struct {
        /*
            counter of id block allocation occurred in idlist_get_new_id(), ideally
            the counter should always stay 0 since all the allocation is expected to
            be detected ahead of time and occurs in idlist_loop_detect_idlist() task
        */
        unsigned int id_block_alloc_cnt;
    } stats;
} idlist_t;

typedef dlist_head_t idlist_list_t;

/*
    id_t conflict with type in system, rename it idlist_id_t
*/
typedef struct _idlist_id {
    dlist_node_t node;
    unsigned int id;
    unsigned int inuse_flag;
} idlist_id_t;

#define IDLIST_GET_ID(idp)                  (((idlist_id_t *)(idp))->id)

static __thread idlist_list_t s_idlist_list;
static __thread unsigned int s_idlist_task_id;

static void idlist_loop_detect_idlist(void *arg __attribute__((unused)))
{
    idlist_t *idl;
    idlist_id_t *idb;
    int i;

    dlist_for_each_node(idl, &s_idlist_list, node) {
        if ((idl->total_id_cnt - idl->inuse_id_cnt) < IDLIST_MIN_NUM_OF_FREE_ID) {
            if (NULL == (idb = mem_d_array_alloc(idl->id_pool))) {
                lune_log(LUNE_WARN, "failed to allocate memory for id list %s", idl->name);
                return;
            }

            for (i = 0; i < IDLIST_NUM_OF_ID_PER_BLOCK; i++) {
                idb[i].id = idl->total_id_cnt++;
                idb[i].inuse_flag = 0;
                dlist_add_tail(&idb[i].node, &idl->free_list);
            }
        }
    }
}

int idlist_local_init(void)
{
    dlist_init_head(&s_idlist_list);
    s_idlist_task_id = LUNE_INVALID_ID;
    return 0;
}

void idlist_local_fini(void)
{
    idlist_t *idl, *idl2;

    dlist_for_each_node_safe(idl, idl2, &s_idlist_list, node) {
        lune_assert(!idlist_delete_list(idl));
    }
}

void *idlist_create_list(const char *name)
{
    idlist_t *idl;
    idlist_id_t *idb;
    int i;

    if (LUNE_INVALID_ID == s_idlist_task_id) {
        /*
            add task only when first id list is created instead of doing so 
            in idlist_local_init() in order to get around issue of task being created
            before sched_local_init(void)
        */
        if (LUNE_INVALID_ID == (s_idlist_task_id = sched_add_task("id list", 
            idlist_loop_detect_idlist, NULL, SCHED_PRIO_BEST_EFFORT))) {
            return NULL;
        }
    }

    if (NULL == name) {
        ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        return NULL;
    }

    if (strlen(name) > LUNE_MAX_SHORT_NAME_LEN) {
        ERR_SET_ERR(LUNE_ERR_NAME_TOO_LONG);
        return NULL;
    }

    if (NULL == (idl = lune_malloc(sizeof(idlist_t)))) {
        goto ERR_1;
    }

    dlist_add_tail(&idl->node, &s_idlist_list);
    dlist_init_head(&idl->free_list);
    dlist_init_head(&idl->inuse_list);
    idl->total_id_cnt = 0;
    idl->inuse_id_cnt = 0;
    strcpy(idl->name, name);
    idl->stats.id_block_alloc_cnt = 0;

    if (NULL == (idl->id_pool = mem_create_d_array("id list",
        sizeof(idlist_id_t) * IDLIST_NUM_OF_ID_PER_BLOCK, IDLIST_NUM_OF_BLOCK))) {
        goto ERR_2;
    }

    if (NULL == (idb = mem_d_array_alloc(idl->id_pool))) {
        goto ERR_3;
    }

    for (i = 0; i < IDLIST_NUM_OF_ID_PER_BLOCK; i++) {
        idb[i].id = idl->total_id_cnt++;
        idb[i].inuse_flag = 0;
        dlist_add_tail(&idb[i].node, &idl->free_list);
    }

    return (void *)idl;

ERR_3:
    mem_delete_d_array(idl->id_pool);

ERR_2:
    dlist_del(&idl->node);
    lune_free((void *)idl);

ERR_1:
    return NULL;
}

int idlist_delete_list(void *idl)
{
    idlist_t *l;

    if (NULL == idl) {
        return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
    }

    l = (idlist_t *)idl;
    if (!dlist_is_empty(&l->inuse_list)) {
        lune_log(LUNE_INFO, "%d ids still in id list %s while deleting it",
            l->inuse_id_cnt, l->name);
    }

    mem_delete_d_array(l->id_pool);
    dlist_del(&l->node);
    lune_free((void *)l);

    /* the same reason for task creation in idlist_create_list() */
    if (dlist_is_empty(&s_idlist_list)) {
        if (LUNE_INVALID_ID != s_idlist_task_id) {
            int err;
            if (0 != (err = sched_del_task(s_idlist_task_id))) {
                return err;
            }
            s_idlist_task_id = LUNE_INVALID_ID;
        }
    }

    return 0;
}

unsigned int idlist_get_new_id(void *idl)
{
    idlist_t *l;
    idlist_id_t *idp, *idb;
    int i;

    if (NULL == idl) {
        ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        return LUNE_INVALID_ID;
    }

    l = (idlist_t *)idl;
    if (!dlist_is_empty(&l->free_list)) {
        idp = dlist_first(&l->free_list, idlist_id_t, node);
        lune_assert(0 == idp->inuse_flag);
        idp->inuse_flag = 1;
        dlist_del(&idp->node);
        dlist_add_tail(&idp->node, &l->inuse_list);
        l->inuse_id_cnt++;
        
        return idp->id;
    }

    if (NULL == (idb = mem_d_array_alloc(l->id_pool))) {
        return LUNE_INVALID_ID;
    }

    idp = &idb[0];
    idp->id = l->total_id_cnt++;
    idp->inuse_flag = 1;
    dlist_add_tail(&idp->node, &l->inuse_list);
    l->inuse_id_cnt++;
    l->stats.id_block_alloc_cnt++;

    for (i = 1; i < IDLIST_NUM_OF_ID_PER_BLOCK; i++) {
        idb[i].id = l->total_id_cnt++;
        idb[i].inuse_flag = 0;
        dlist_add_tail(&idb[i].node, &l->free_list);
    }

    return idp->id;
}

int idlist_del_id(unsigned int id, void *idl)
{
    idlist_t *l;
    idlist_id_t *idp, *idb;
    int idx;

    if (NULL == idl || LUNE_INVALID_ID == id || ((idlist_t *)idl)->total_id_cnt <= id) {
        return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
    }

    l = (idlist_t *)idl;
    idx = id >> IDLIST_NUM_OF_ID_PER_BLOCK_IN_BIT;
    if (NULL == (idb = mem_d_array_get(l->id_pool, idx))) {
        return ERR_GET_LAST_ERR();
    }

    idp = &idb[IDLIST_ID_PER_BLOCK_MASK & id];

    lune_assert(1 == idp->inuse_flag);
    idp->inuse_flag = 0;
    dlist_del(&idp->node);
    dlist_add_tail(&idp->node, &l->free_list);
    l->inuse_id_cnt--;
    lune_assert((int)l->inuse_id_cnt >= 0);

    return 0;
}
