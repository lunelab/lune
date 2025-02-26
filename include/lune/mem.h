/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2024 Lune Reseau, Inc.
 */

#ifndef __LUNE_MEM_H__
#define __LUNE_MEM_H__

/*
    for build of LUNE and its built-in APPs, use build_conf.h generated during the build
    for build of any other independent APP, use build_conf.h already installed
*/
#ifdef LUNE_BUILD
#include "build/build_conf.h"
#else
#include "lune/build_conf.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* single-threaded malloc */
typedef void *(*lune_mem_alloc_st_func_t)(unsigned int);
/* single-threaded free */
typedef void (*lune_mem_free_st_func_t)(void *);
/* multi-threaded malloc */
typedef void *(*lune_mem_alloc_mt_func_t)(unsigned int);
/* multi-threaded free */
typedef void (*lune_mem_free_mt_func_t)(void *);

typedef struct _lune_mem_func_set {
    lune_mem_alloc_st_func_t _mem_alloc_st;
    lune_mem_free_st_func_t _mem_free_st;
    lune_mem_alloc_mt_func_t _mem_alloc_mt;
    lune_mem_free_mt_func_t _mem_free_mt;
} lune_mem_func_set_t;

/* thread-unsafe, suffix _x for bulk memory */
#if LUNE_MEM_DBG_PRINT
#define lune_malloc(s)      __lune_malloc_dbg(s, __FILE__, __LINE__)
#define lune_free(p)        __lune_free_dbg(p, __FILE__, __LINE__)
#define lune_malloc_x(s)    __lune_malloc_x_dbg(s, __FILE__, __LINE__)
#define lune_free_x(p)      __lune_free_x_dbg(p, __FILE__, __LINE__)
#else
#define lune_malloc(s)      __lune_malloc(s)
#define lune_free(p)        __lune_free(p)
#define lune_malloc_x(s)    __lune_malloc_x(s)
#define lune_free_x(p)      __lune_free_x(p)
#endif

void *__lune_malloc(unsigned int size);
void __lune_free(void *p);
void *__lune_malloc_x(unsigned int size);
void __lune_free_x(void *p);

void *__lune_malloc_dbg(unsigned int size, const char *file_name, int line_no);
void __lune_free_dbg(void *p, const char *file_name, int line_no);
void *__lune_malloc_x_dbg(unsigned int size, const char *file_name, int line_no);
void __lune_free_x_dbg(void *p, const char *file_name, int line_no);

/* thread-safe, suffix _x for bulk memory */
#if LUNE_MEM_DBG_PRINT
#define lune_malloc_mt(s)   __lune_malloc_mt_dbg(s, __FILE__, __LINE__)
#define lune_free_mt(p)     __lune_free_mt_dbg(p, __FILE__, __LINE__)
#define lune_malloc_x_mt(s) __lune_malloc_x_mt_dbg(s, __FILE__, __LINE__)
#define lune_free_x_mt(p)   __lune_free_x_mt_dbg(p, __FILE__, __LINE__)
#else
#define lune_malloc_mt(s)   __lune_malloc_mt(s)
#define lune_free_mt(p)     __lune_free_mt(p)
#define lune_malloc_x_mt(s) __lune_malloc_x_mt(s)
#define lune_free_x_mt(p)   __lune_free_x_mt(p)
#endif

void *__lune_malloc_mt(unsigned int size);
void __lune_free_mt(void *p);
void *__lune_malloc_x_mt(unsigned int size);
void __lune_free_x_mt(void *p);

void *__lune_malloc_mt_dbg(unsigned int size, const char *file_name, int line_no);
void __lune_free_mt_dbg(void *p, const char *file_name, int line_no);
void *__lune_malloc_x_mt_dbg(unsigned int size, const char *file_name, int line_no);
void __lune_free_x_mt_dbg(void *p, const char *file_name, int line_no);

/* thread-unsafe */
void *lune_create_mem_pool(const char *name, unsigned int size);
int lune_delete_mem_pool(void *pool);
void *lune_mem_pool_alloc(void *pool);
void lune_mem_pool_free(void *pool, void *p);

int lune_reg_mem_funcs(lune_mem_func_set_t *func_set);
void lune_unreg_mem_funcs(void);

#ifdef __cplusplus
}
#endif

#endif