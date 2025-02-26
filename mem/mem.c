/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2024 Lune Reseau, Inc.
 */

#include "lune/assert.h"
#include "lune/atomic.h"
#include "lune/cpu.h"
#include "lune/common.h"
#include "lune/id.h"
#include "lune/list.h"
#include "lune/log.h"
#include "lune/os/linux.h"
#include "lune/time.h"
#include "lune/timer.h"

#include "err/err.h"
#include "kernel/sched.h"
#include "lib/common.h"
#include "mem/mem.h"
#include "rt/core.h"

#define NUM_IS_ODD(num)             ((num) & 0x01)

typedef struct {
    unsigned int size;
    unsigned int rsvd;
} mem_hdr_t;

#ifdef LUNE_BUILD_MEM_DBG_OOB_L1
#define MEM_GAP_FLAG_MALLOC         (0xdeadbeef)
#define MEM_GAP_FLAG_FREE           (0xbeefdead)
#ifdef LUNE_BUILD_MEM_DBG_OOB_L2
#define MEM_GAP_FLAG_CNT            (20)
#else
#define MEM_GAP_FLAG_CNT            (2)
#endif
typedef struct {
    unsigned int flags[MEM_GAP_FLAG_CNT];
} mem_gap_t;
#endif

typedef struct {
    long long total_bytes;
    long long total_inuse_bytes;
} mem_stats_st_t;

typedef struct {
    lune_atomic64_t total_bytes;
    lune_atomic64_t total_inuse_bytes;
} mem_stats_mt_t;

static lune_mem_func_set_t s_mem_func_set = {
    ._mem_alloc_st = (lune_mem_alloc_st_func_t)malloc,
    ._mem_free_st = (lune_mem_free_st_func_t)free,
    ._mem_alloc_mt = (lune_mem_alloc_mt_func_t)malloc,
    ._mem_free_mt = (lune_mem_free_mt_func_t)free,
};

static __thread mem_stats_st_t s_mem_stats_st;
static __thread lune_timer_t s_mem_stats_st_tmr;

static mem_stats_mt_t s_mem_stats_mt;

int lune_reg_mem_funcs(lune_mem_func_set_t *func_set)
{
    if (unlikely(NULL == func_set)) {
        return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
    }

    memcpy(&s_mem_func_set, func_set, sizeof(lune_mem_func_set_t));
    return 0;
}

void lune_unreg_mem_funcs(void)
{
    s_mem_func_set._mem_alloc_st = (lune_mem_alloc_st_func_t)malloc;
    s_mem_func_set._mem_free_st = (lune_mem_free_st_func_t)free;
    s_mem_func_set._mem_alloc_mt = (lune_mem_alloc_mt_func_t)malloc;
    s_mem_func_set._mem_free_mt = (lune_mem_free_mt_func_t)free;
}

static inline void *__lune_malloc_mt_int(unsigned int size)
{
    mem_hdr_t *p;
    unsigned int s = size + sizeof(mem_hdr_t);

    if (NULL == (p = s_mem_func_set._mem_alloc_mt(s))) {
        ERR_SET_ERR(LUNE_ERR_NO_MEM);
        return NULL;
    }

    p->size = size;
    p->rsvd = 0;

    lune_atomic64_add(&s_mem_stats_mt.total_bytes, s);
    lune_atomic64_add(&s_mem_stats_mt.total_inuse_bytes, s);

    return (unsigned char *)p + sizeof(mem_hdr_t);
}

void *__lune_malloc_mt(unsigned int size)
{
    return __lune_malloc_mt_int(size);
}

void *__lune_malloc_mt_dbg(unsigned int size, const char *file_name, int line_no)
{
    void *p;

    if (NULL != (p = __lune_malloc_mt_int(size))) {
        lune_log(LUNE_INFO, "[MEMPRINT] lune_malloc_mt: %p size(%d) file(%s) line(%d) core(%d)",
            p, size, file_name, line_no, CORE_GET_ID());
    }

    return p;
}

static inline void __lune_free_mt_int(void *p)
{
    mem_hdr_t *mh;
    unsigned int s;

    mh = (mem_hdr_t *)((unsigned char *)p - sizeof(mem_hdr_t));
    s = mh->size + sizeof(mem_hdr_t);

    lune_atomic64_sub(&s_mem_stats_mt.total_bytes, s);
    lune_atomic64_sub(&s_mem_stats_mt.total_inuse_bytes, s);

    s_mem_func_set._mem_free_mt((void *)mh);
}

void __lune_free_mt(void *p)
{
    if (unlikely(NULL == p)) {
        lune_log(LUNE_INFO, "free NULL pointer in __lune_free_mt");
        return;
    }

    __lune_free_mt_int(p);
}

void __lune_free_mt_dbg(void *p, const char *file_name, int line_no)
{
    mem_hdr_t *mh;

    if (unlikely(NULL == p)) {
        lune_log(LUNE_INFO, "free NULL pointer in __lune_free_mt_dbg");
        return;
    }

    mh = (mem_hdr_t *)((unsigned char *)(p) - sizeof(mem_hdr_t));
    lune_log(LUNE_INFO, "[MEMPRINT] lune_free_mt: %p size(%d) file(%s) line(%d) core(%d)",
        p, mh->size, file_name, line_no, CORE_GET_ID());

    __lune_free_mt_int(p);
}

static inline void *__lune_malloc_int(unsigned int size)
{
#ifdef LUNE_BUILD_MEM_DBG_OOB_L1
    unsigned int s = size + sizeof(mem_hdr_t) + sizeof(mem_gap_t) * 2;
#else
    unsigned int s = size + sizeof(mem_hdr_t);
#endif

    mem_hdr_t *p = (mem_hdr_t *)s_mem_func_set._mem_alloc_st(s);
    if (NULL == p) {
        ERR_SET_ERR(LUNE_ERR_NO_MEM);
        return NULL;
    }

    p->size = size;
    p->rsvd = 0;

    s_mem_stats_st.total_bytes += s;
    s_mem_stats_st.total_inuse_bytes += s;

#ifdef LUNE_BUILD_MEM_DBG_OOB_L1
    {
        int i;
        unsigned int *flag_start, *flag_end;

        flag_start = (unsigned int *)((unsigned char *)p + sizeof(mem_hdr_t));
        flag_end = (unsigned int *)((unsigned char *)p + s);
        for (i = 0; i < MEM_GAP_FLAG_CNT; i++) {
            *(flag_start + i) = MEM_GAP_FLAG_MALLOC;
            *(flag_end - i - 1) = MEM_GAP_FLAG_MALLOC;
        }
    }
#ifdef LUNE_BUILD_MEM_DBG_OOB_L2
    memset((unsigned char *)p + sizeof(mem_hdr_t) + sizeof(mem_gap_t), 0xff, size);
#endif
    return (unsigned char *)p + sizeof(mem_hdr_t) + sizeof(mem_gap_t);
#else
    return (unsigned char *)p + sizeof(mem_hdr_t);
#endif
}

void *__lune_malloc(unsigned int size)
{
    return __lune_malloc_int(size);
}

void *__lune_malloc_dbg(unsigned int size, const char *file_name, int line_no)
{
    void *p;

    if (NULL != (p = __lune_malloc_int(size))) {
        lune_log(LUNE_INFO, "[MEMPRINT] lune_malloc: %p size(%d) file(%s) line(%d) core(%d)",
            p, size, file_name, line_no, CORE_GET_ID());
    }

    return p;
}

static inline void __lune_free_int(void *p)
{
    mem_hdr_t *mh;
    unsigned int s;

#ifdef LUNE_BUILD_MEM_DBG_OOB_L1
    mh = (mem_hdr_t *)((unsigned char *)p - sizeof(mem_hdr_t) - sizeof(mem_gap_t));
    s = mh->size + sizeof(mem_hdr_t) + sizeof(mem_gap_t) * 2;
#ifdef LUNE_BUILD_MEM_DBG_OOB_L2
    memset((unsigned char *)p, 0xff, mh->size);
#endif
    {
        int i;
        unsigned int *flag_start, *flag_end;

        flag_start = (unsigned int *)((unsigned char *)p - sizeof(mem_gap_t));
        flag_end = (unsigned int *)((unsigned char *)p + mh->size + sizeof(mem_gap_t));
        for (i = 0; i < MEM_GAP_FLAG_CNT; i++) {
            lune_assert(MEM_GAP_FLAG_MALLOC == *(flag_start + i));
            *(flag_start + i) = MEM_GAP_FLAG_FREE;
            lune_assert(MEM_GAP_FLAG_MALLOC == *(flag_end - i - 1));
            *(flag_end - i - 1) = MEM_GAP_FLAG_FREE;
        }
    }
#else
    mh = (mem_hdr_t *)((unsigned char *)p - sizeof(mem_hdr_t));
    s = mh->size + sizeof(mem_hdr_t);
#endif
    s_mem_stats_st.total_bytes -= s;
    s_mem_stats_st.total_inuse_bytes -= s;

    lune_assert(s_mem_stats_st.total_bytes >= 0);
    lune_assert(s_mem_stats_st.total_inuse_bytes >= 0);

    s_mem_func_set._mem_free_st((void *)mh);
}

void __lune_free(void *p)
{
    if (unlikely(NULL == p)) {
        lune_log(LUNE_INFO, "free NULL pointer in __lune_free");
        return;
    }

    __lune_free_int(p);
}

void __lune_free_dbg(void *p, const char *file_name, int line_no)
{
    mem_hdr_t *mh;

    if (unlikely(NULL == p)) {
        lune_log(LUNE_INFO, "free NULL pointer in __lune_free_dbg");
        return;
    }

#ifdef LUNE_BUILD_MEM_DBG_OOB_L1
    mh = (mem_hdr_t *)((unsigned char *)(p) - sizeof(mem_hdr_t) - sizeof(mem_gap_t));
#else
    mh = (mem_hdr_t *)((unsigned char *)(p) - sizeof(mem_hdr_t));
#endif
    lune_log(LUNE_INFO, "[MEMPRINT] lune_free: %p size(%d) file(%s) line(%d) core(%d)",
        p, mh->size, file_name, line_no, CORE_GET_ID());

    __lune_free_int(p);
}

/* dynamic array */

typedef dlist_head_t mem_d_array_list_t;

static __thread mem_d_array_list_t s_mem_d_array_list;

void *mem_create_d_array(const char *name,
    unsigned int elem_size, unsigned int array_size)
{
    mem_d_array_t *ma;
    unsigned int i;

    if (NULL == name
        || 0 == elem_size
        || 0 == array_size) {
        goto ERR_1;
    }

    if (NULL == (ma = lune_malloc(sizeof(mem_d_array_t)))) {
        goto ERR_1;
    }

    if (NULL == (ma->array = lune_malloc(sizeof(void *) * array_size))) {
        goto ERR_2;
    }

    if (NULL == (ma->array[0] = lune_malloc(elem_size))) {
        goto ERR_3;
    }

    for (i = 1; i < array_size; i++) {
        ma->array[i] = NULL;
    }
    ma->array_size = array_size;
    ma->elem_size = elem_size;
    ma->last = 0;
    strcpy(ma->name, name);

    dlist_add_tail(&ma->node, &s_mem_d_array_list);

    return ma;

ERR_3:
    lune_free(ma->array);

ERR_2:
    lune_free(ma);

ERR_1:
    return NULL;
}

void mem_delete_d_array(void *array)
{
    mem_d_array_t *ma = (mem_d_array_t *)array;
    unsigned int i;

    lune_assert(NULL != ma);

    dlist_del(&ma->node);

    for (i = 0; i < ma->array_size; i++) {
        if (NULL != ma->array[i]) {
            lune_free(ma->array[i]);
            ma->array[i] = NULL;
        }
    }

    lune_free(ma->array);
    lune_free(ma);
}

void *mem_d_array_alloc(void *array)
{
    mem_d_array_t *ma;

    if (unlikely(NULL == array)) {
        ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        return NULL;
    }

    ma = (mem_d_array_t *)array;
    if (ma->last >= ma->array_size) {
        ERR_SET_ERR(LUNE_ERR_MEM_OVERFLOW);
        return NULL;
    }

    if (NULL == ma->array[ma->last]) {
        if (NULL == (ma->array[ma->last] = lune_malloc(ma->elem_size))) {
            return NULL;
        }
    }

    return ma->array[ma->last++];
}

/* static array */

typedef dlist_head_t mem_s_array_list_t;

static __thread mem_s_array_list_t s_mem_s_array_list;

void *mem_create_s_array(const char *name,
    unsigned int elem_size, unsigned int array_size, mem_s_array_init_func_t func)
{
    mem_s_array_t *ma;
    unsigned int i;

    if (NULL == name
        || 0 == elem_size
        || 0 == array_size) {
        goto ERR_1;
    }

    if (NULL == (ma = lune_malloc(sizeof(mem_s_array_t) + array_size))) {
        goto ERR_1;
    }

    if (NULL == (ma->array = lune_malloc(
        ALIGN_8B(sizeof(mem_s_array_elem_hdr_t) + elem_size) * array_size))) {
        goto ERR_2;
    }

    dlist_init_head(&ma->free_list_head);
    for (i = 0; i < array_size; i++) {
        dlist_add_tail(&((mem_s_array_elem_hdr_t *)((unsigned char *)ma->array
            + i * (sizeof(mem_s_array_elem_hdr_t) + elem_size)))->node, &ma->free_list_head);
        if (NULL != func) {
            func((unsigned char *)ma->array
                + i * (sizeof(mem_s_array_elem_hdr_t) + elem_size) + sizeof(mem_s_array_elem_hdr_t));
        }
    }
    ma->array_size = array_size;
    ma->elem_size = elem_size;
    strcpy(ma->name, name);

    dlist_add_tail(&ma->node, &s_mem_s_array_list);

    return ma;

ERR_2:
    lune_free(ma);

ERR_1:
    return NULL;
}

void mem_delete_s_array(void *array, mem_s_array_free_func_t func)
{
    mem_s_array_t *ma = (mem_s_array_t *)array;
    unsigned int i;

    lune_assert(NULL != ma);

    dlist_del(&ma->node);

    for (i = 0; i < ma->array_size; i++) {
        if (dlist_is_empty(&((mem_s_array_elem_hdr_t *)((unsigned char *)ma->array
            + i * (sizeof(mem_s_array_elem_hdr_t) + ma->elem_size)))->node)) {
            if (NULL != func) {
                func((unsigned char *)ma->array + i * (sizeof(mem_s_array_elem_hdr_t)
                    + ma->elem_size) + sizeof(mem_s_array_elem_hdr_t));
            }
        }
    }

    lune_free(ma->array);
    lune_free(ma);
}

void *mem_s_array_alloc(void *array)
{
    mem_s_array_t *ma;
    mem_s_array_elem_hdr_t *p;

    if (unlikely(NULL == array)) {
        ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        return NULL;
    }

    ma = (mem_s_array_t *)array;
    if (dlist_is_empty(&ma->free_list_head)) {
        ERR_SET_ERR(LUNE_ERR_NO_MEM);
        return NULL;
    }

    p = dlist_first(&ma->free_list_head, mem_s_array_elem_hdr_t, node);
    dlist_del_init(&p->node);
    return (void *)((unsigned char *)p + sizeof(mem_s_array_elem_hdr_t));
}

void mem_s_array_free(void *array, void *elem)
{
    mem_s_array_t *ma = (mem_s_array_t *)array;
    mem_s_array_elem_hdr_t *p;

    if (unlikely(NULL == ma || NULL == elem)) {
        lune_log(LUNE_WARN, "failed to free memory in static array %s: %s",
            ma->name, ERR_GET_ERR_STR(ERR_SET_ERR(LUNE_ERR_MEM_INTERNAL)));
        return;
    }

    p = (mem_s_array_elem_hdr_t *)((unsigned char *)elem - sizeof(mem_s_array_elem_hdr_t));

    lune_assert(!dlist_node_is_added(&p->node));
    dlist_add_head(&p->node, &ma->free_list_head);
}

/* fixed-size pool */

typedef struct _mem_pool_slice_hdr {
    dlist_node_t node;
    unsigned long long offset;
} mem_pool_slice_hdr_t;

typedef struct _mem_pool_slice_first_hdr {
    unsigned int inuse_cnt;
    unsigned int free_cnt;
    mem_pool_slice_hdr_t hdr; 
} mem_pool_slice_first_hdr_t;

typedef struct _mem_pool {
    char name[LUNE_MAX_SHORT_NAME_BUF_LEN];
    dlist_node_t node;
    dlist_head_t free_list;
    dlist_head_t inuse_list;
    int free_cnt;
    int inuse_cnt;
    unsigned int size;
    unsigned int task_id;
} mem_pool_t;

typedef dlist_head_t mem_pool_list_t;

static __thread mem_pool_list_t s_mem_pool_list;

#define MEM_POOL_INIT_MEM_NUM               (512)
#define MEM_POOL_MEM_NUM_THRESHOLD          (128)
#define MEM_POOL_INCREASE_MEM_NUM           (128)

static inline int mem_pool_alloc_mems(mem_pool_t *mp, unsigned int cnt)
{
    unsigned int i;
    mem_pool_slice_hdr_t *hdr;
    mem_pool_slice_first_hdr_t *first_hdr;

    if (NULL == (first_hdr =
        lune_malloc((sizeof(mem_pool_slice_hdr_t) + mp->size) * (cnt - 1)
        + sizeof(mem_pool_slice_first_hdr_t) + mp->size))) {
        lune_log(LUNE_INFO, "failed to allocate memory for memory pool %s", mp->name);
        return ERR_GET_LAST_ERR();
    }

    for (i = 0, hdr = &first_hdr->hdr; i < cnt; i++) {
        hdr->offset = (unsigned char *)hdr - (unsigned char *)first_hdr;
        dlist_add_tail(&hdr->node, &mp->free_list);
        hdr = (mem_pool_slice_hdr_t *)((unsigned char *)hdr
            + (sizeof(mem_pool_slice_hdr_t) + mp->size));
    }
    first_hdr->free_cnt = cnt;
    first_hdr->inuse_cnt = 0;

    mp->free_cnt += cnt;

    return 0;
}

static void mem_pool_free_all_mems(mem_pool_t *mp)
{
    mem_pool_slice_hdr_t *hdr, *hdr2;
    mem_pool_slice_first_hdr_t *first_hdr;
    dlist_head_t *free_list_head = &mp->free_list;

    dlist_for_each_node_safe(hdr, hdr2, free_list_head, node) {
        first_hdr = (mem_pool_slice_first_hdr_t *)((unsigned char *)hdr - hdr->offset);

        dlist_del_init(&hdr->node);
        first_hdr->free_cnt--;

        if (0 == first_hdr->inuse_cnt
            && 0 == first_hdr->free_cnt) {
            /* free the whole slice */
            lune_free(first_hdr);
        }

        mp->free_cnt--;
    }
}

static void mem_pool_loop_detect_pool(void *arg)
{
    mem_pool_t *mp = (mem_pool_t *)arg;

    if (mp->free_cnt > MEM_POOL_MEM_NUM_THRESHOLD) {
        return;
    }

    (void)mem_pool_alloc_mems(mp, MEM_POOL_INCREASE_MEM_NUM);
}

void *lune_create_mem_pool(const char *name, unsigned int size)
{
    mem_pool_t *mp;

    if (NULL == name || 0 == size) {
        ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
        goto ERR_1;
    }

    if (strlen(name) > LUNE_MAX_SHORT_NAME_LEN) {
        ERR_SET_ERR(LUNE_ERR_NAME_TOO_LONG);
        goto ERR_1;
    }

    if (NULL == (mp = lune_malloc(sizeof(mem_pool_t)))) {
        goto ERR_1;
    }

    strcpy(mp->name, name);
    lune_str_replace_char(mp->name, ' ', '_');
    mp->size = size;

    dlist_init_head(&mp->free_list);
    mp->free_cnt = 0;
    if (mem_pool_alloc_mems(mp, MEM_POOL_INIT_MEM_NUM)) {
        goto ERR_2;
    }

    dlist_init_head(&mp->inuse_list);
    mp->inuse_cnt = 0;

    if (LUNE_INVALID_ID == (mp->task_id = sched_add_task(mp->name,
        mem_pool_loop_detect_pool, (void *)mp, SCHED_PRIO_BEST_EFFORT))) {
        goto ERR_3;
    }

    dlist_add_tail(&mp->node, &s_mem_pool_list);

    return (void *)mp;

ERR_3:
    mem_pool_free_all_mems(mp);

ERR_2:
    lune_free(mp);

ERR_1:
    return NULL;
}

int lune_delete_mem_pool(void *pool)
{
    mem_pool_t *mp = (mem_pool_t *)pool;

    if (NULL == mp) {
        return ERR_SET_ERR(LUNE_ERR_INVALID_ARG);
    }

    lune_assert(!sched_del_task(mp->task_id));

    if (0 != mp->inuse_cnt) {
        lune_log(LUNE_INFO, "%d still in memory pool %s while deleting it",
            mp->inuse_cnt, mp->name);
    }

    mem_pool_free_all_mems(mp);

    dlist_del(&mp->node);

    if (0 != mp->free_cnt) {
        lune_log(LUNE_INFO, "internal error (%d) of memory pool %s", mp->free_cnt, mp->name);
        lune_free(mp);
        return ERR_SET_ERR(LUNE_ERR_MEM_INTERNAL);
    }

    lune_free(mp);
    return 0;
}

void *lune_mem_pool_alloc(void *pool)
{
    mem_pool_t *mp = (mem_pool_t *)pool;
    mem_pool_slice_hdr_t *hdr;
    mem_pool_slice_first_hdr_t *first_hdr;
    dlist_head_t *free_list_head;

    lune_assert(NULL != mp);

    if (likely(mp->free_cnt > 0)) {
        goto MEM_AVAIL;
    }

    lune_log_once(LUNE_DBG, "memory pool %s just ran out of memory", mp->name);

    if (mem_pool_alloc_mems(mp, MEM_POOL_INCREASE_MEM_NUM)) {
        return NULL;
    }

MEM_AVAIL:
    free_list_head = &mp->free_list;
    hdr = dlist_first(free_list_head, mem_pool_slice_hdr_t, node);
    first_hdr = (mem_pool_slice_first_hdr_t *)((unsigned char *)hdr - hdr->offset);

    dlist_del(&hdr->node);
    first_hdr->free_cnt--;
    mp->free_cnt--;

    dlist_add_tail(&hdr->node, &mp->inuse_list);
    first_hdr->inuse_cnt++;
    mp->inuse_cnt++;

    return (void *)((unsigned char *)hdr + sizeof(mem_pool_slice_hdr_t));
}

void lune_mem_pool_free(void *pool, void *p)
{
    mem_pool_t *mp = (mem_pool_t *)pool;
    mem_pool_slice_hdr_t *hdr;
    mem_pool_slice_first_hdr_t *first_hdr;

    lune_assert(NULL != mp && NULL != p);

    hdr = (mem_pool_slice_hdr_t *)((unsigned char *)p - sizeof(mem_pool_slice_hdr_t));
    first_hdr = (mem_pool_slice_first_hdr_t *)((unsigned char *)hdr - hdr->offset);

    dlist_del(&hdr->node);
    first_hdr->inuse_cnt--;
    mp->inuse_cnt--;

    /* add it to head so it will be picked first */
    dlist_add_head(&hdr->node, &mp->free_list);
    first_hdr->free_cnt++;
    mp->free_cnt++;
}

static inline void *__lune_malloc_x_mt_int(unsigned int size)
{
    mem_hdr_t *p;
    unsigned int s = size + sizeof(mem_hdr_t);

    if (NULL == (p = s_mem_func_set._mem_alloc_mt(size))) {
        ERR_SET_ERR(LUNE_ERR_NO_MEM);
        return NULL;
    }

    p->size = size;
    p->rsvd = 0;

    lune_atomic64_add(&s_mem_stats_mt.total_bytes, s);
    lune_atomic64_add(&s_mem_stats_mt.total_inuse_bytes, s);

    return (unsigned char *)p + sizeof(mem_hdr_t);
}

void *__lune_malloc_x_mt(unsigned int size)
{
    return __lune_malloc_x_mt_int(size);
}

void *__lune_malloc_x_mt_dbg(unsigned int size, const char *file_name, int line_no)
{
    void *p;

    if (NULL != (p = __lune_malloc_x_mt_int(size))) {
        lune_log(LUNE_INFO, "[MEMPRINT] lune_malloc_x_mt: %p size(%d) file(%s) line(%d) core(%d)",
            p, size, file_name, line_no, CORE_GET_ID());
    }

    return p;
}

static inline void __lune_free_x_mt_int(void *p)
{
    mem_hdr_t *mh;
    unsigned int s;

    mh = (mem_hdr_t *)((unsigned char *)p - sizeof(mem_hdr_t));
    s = mh->size + sizeof(mem_hdr_t);

    lune_atomic64_sub(&s_mem_stats_mt.total_bytes, s);
    lune_atomic64_sub(&s_mem_stats_mt.total_inuse_bytes, s);

    s_mem_func_set._mem_free_mt((void *)mh);
}

void __lune_free_x_mt(void *p)
{
    if (unlikely(NULL == p)) {
        lune_log(LUNE_INFO, "free NULL pointer in __lune_free_x_mt");
        return;
    }

    __lune_free_x_mt_int(p);
}

void __lune_free_x_mt_dbg(void *p, const char *file_name, int line_no)
{
    mem_hdr_t *mh;

    if (unlikely(NULL == p)) {
        lune_log(LUNE_INFO, "free NULL pointer in __lune_free_x_mt_dbg");
        return;
    }

    mh = (mem_hdr_t *)((unsigned char *)(p) - sizeof(mem_hdr_t));
    lune_log(LUNE_INFO, "[MEMPRINT] lune_free_x_mt: %p size(%d) file(%s) line(%d) core(%d)",
        p, mh->size, file_name, line_no, CORE_GET_ID());

    __lune_free_x_mt_int(p);
}

static inline void *__lune_malloc_x_int(unsigned int size)
{
    mem_hdr_t *p;
    unsigned int s;

    s = size + sizeof(mem_hdr_t);
    if (NULL == (p = (mem_hdr_t *)s_mem_func_set._mem_alloc_st(s))) {
        ERR_SET_ERR(LUNE_ERR_NO_MEM);
        return NULL;
    }

    p->size = size;
    p->rsvd = 0;
#ifdef LUNE_BUILD_MEM_DBG_OOB_L1
    memset((unsigned char *)p + sizeof(mem_hdr_t), 0xff, size);
#endif

    s_mem_stats_st.total_bytes += s;
    s_mem_stats_st.total_inuse_bytes += s;

    return (unsigned char *)p + sizeof(mem_hdr_t);
}

void *__lune_malloc_x(unsigned int size)
{
    return __lune_malloc_x_int(size);
}

void *__lune_malloc_x_dbg(unsigned int size, const char *file_name, int line_no)
{
    void *p;

    if (NULL != (p = __lune_malloc_x_int(size))) {
        lune_log(LUNE_INFO, "[MEMPRINT] lune_malloc_x: %p size(%d) file(%s) line(%d) core(%d)",
            p, size, file_name, line_no, CORE_GET_ID());
    }

    return p;
}

static inline void __lune_free_x_int(void *p)
{
    mem_hdr_t *mh;
    unsigned int s;

    mh = (mem_hdr_t *)((unsigned char *)p - sizeof(mem_hdr_t));
    s = mh->size + sizeof(mem_hdr_t);
#ifdef LUNE_BUILD_MEM_DBG_OOB_L1
    memset((unsigned char *)p, 0xff, mh->size);
#endif
    s_mem_stats_st.total_bytes -= s;
    s_mem_stats_st.total_inuse_bytes -= s;

    lune_assert(s_mem_stats_st.total_bytes >= 0);
    lune_assert(s_mem_stats_st.total_inuse_bytes >= 0);

    s_mem_func_set._mem_free_st((void *)mh);
}

void __lune_free_x(void *p)
{
    if (unlikely(NULL == p)) {
        lune_log(LUNE_INFO, "free NULL pointer in __lune_free_x");
        return;
    }

    __lune_free_x_int(p);
}

void __lune_free_x_dbg(void *p, const char *file_name, int line_no)
{
    mem_hdr_t *mh;

    if (unlikely(NULL == p)) {
        lune_log(LUNE_INFO, "free NULL pointer in __lune_free_x_dbg");
        return;
    }

    mh = (mem_hdr_t *)((unsigned char *)(p) - sizeof(mem_hdr_t));
    lune_log(LUNE_INFO, "[MEMPRINT] lune_free_x: %p size(%d) file(%s) line(%d) core(%d)",
        p, mh->size, file_name, line_no, CORE_GET_ID());

    __lune_free_x_int(p);
}

#ifdef LUNE_DEBUG
static void mem_report_local_mem_stats(void)
{
    lune_log(LUNE_INFO, "[MEMSTAT] local memory total bytes %lld, total bytes in use %lld",
        s_mem_stats_st.total_bytes, s_mem_stats_st.total_inuse_bytes);
}

int mem_start_local_mem_stats_report(void)
{
    lune_assert(!LUNE_TIMER_IS_ADDED(s_mem_stats_st_tmr));

    timer_init_timer(&s_mem_stats_st_tmr,
        LUNE_TIMER_RECURRING, LUNE_TIMER_RES_DEFAULT, (lune_timer_func_t)mem_report_local_mem_stats, NULL);
    timer_add_timer(&s_mem_stats_st_tmr, 1 * LUNE_TIME_SECOND);

    return 0;
}

void mem_stop_local_mem_stats_report(void)
{
    lune_assert(LUNE_TIMER_IS_ADDED(s_mem_stats_st_tmr));
    timer_del_timer(&s_mem_stats_st_tmr);
}
#endif

int mem_local_init(void)
{
    s_mem_stats_st.total_bytes = 0;
    s_mem_stats_st.total_inuse_bytes = 0;

    LUNE_TIMER_MINI_INIT(s_mem_stats_st_tmr);

    dlist_init_head(&s_mem_d_array_list);
    dlist_init_head(&s_mem_s_array_list);
    dlist_init_head(&s_mem_pool_list);

    return 0;
}

void mem_local_fini(void)
{
#ifdef LUNE_DEBUG
    fprintf(stdout, "local memory total bytes %lld, total bytes in use %lld on core %d while quitting\n",
        s_mem_stats_st.total_bytes, s_mem_stats_st.total_inuse_bytes, CORE_GET_ID());
#endif

    lune_assert(dlist_is_empty(&s_mem_pool_list));
    lune_assert(dlist_is_empty(&s_mem_s_array_list));
    lune_assert(dlist_is_empty(&s_mem_d_array_list));

    s_mem_stats_st.total_bytes = 0;
    s_mem_stats_st.total_inuse_bytes = 0;

    return;
}

int mem_init(void)
{
    lune_atomic64_set(&s_mem_stats_mt.total_bytes, 0);
    lune_atomic64_set(&s_mem_stats_mt.total_inuse_bytes, 0);
    return 0;
}

void mem_fini(void)
{
#ifdef LUNE_DEBUG
    fprintf(stdout, "global memory total bytes %lld, total bytes in use %lld while quitting\n",
        lune_atomic64_get(&s_mem_stats_mt.total_bytes), lune_atomic64_get(&s_mem_stats_mt.total_inuse_bytes));
#endif
    lune_atomic64_set(&s_mem_stats_mt.total_bytes, 0);
    lune_atomic64_set(&s_mem_stats_mt.total_inuse_bytes, 0);
    return;
}
