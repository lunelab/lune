/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2024 Lune Reseau, Inc.
 */

#ifndef __LUNE_ATOMIC_H__
#define __LUNE_ATOMIC_H__

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __x86_64__
#define lune_smp_mb()   asm volatile("lock addl $0, -128(%%rsp); " ::: "memory")
#define lune_smp_wmb()  asm volatile ("" : : : "memory")
#define lune_smp_rmb()  asm volatile ("" : : : "memory")
#else
#error "not supported"
#endif

typedef volatile short lune_atomic16_t;
typedef volatile int lune_atomic32_t;
typedef volatile long long lune_atomic64_t;
typedef void *lune_atomic_ptr_t;

static inline short lune_atomic16_get(lune_atomic16_t *a)
{
    return *a;
}

static inline void lune_atomic16_set(lune_atomic16_t *a, short v)
{
    *a = v;
}

static inline void lune_atomic16_inc(lune_atomic16_t *a)
{
    (void)__sync_add_and_fetch(a, 1);
}

static inline short lune_atomic16_inc_and_return(lune_atomic16_t *a)
{
    return __sync_add_and_fetch(a, 1);
}

static inline void lune_atomic16_dec(lune_atomic16_t *a)
{
    (void)__sync_sub_and_fetch(a, 1);
}

static inline void lune_atomic16_add(lune_atomic16_t *a, short v)
{
    (void)__sync_add_and_fetch(a, v);
}

static inline void lune_atomic16_sub(lune_atomic16_t *a, short v)
{
    (void)__sync_sub_and_fetch(a, v);
}

static inline int lune_atomic16_dec_is_zero(lune_atomic16_t *a)
{
    return (0 == __sync_sub_and_fetch(a, 1));
}

/*
    (atomic) equivalent to:
    if (*dst == exp)
        *dst = src
    return:
        Non-zero on success; 0 on failure
*/
static inline int lune_atomic16_cmpset(lune_atomic16_t *dst, short exp, short src)
{
    char res;

    asm volatile(
            "lock;"
            "cmpxchgw %[src], %[dst];"
            "sete %[res];"
            : [res] "=a" (res),     /* output */
              [dst] "=m" (*dst)
            : [src] "r" (src),      /* input */
              "a" (exp),
              "m" (*dst)
            : "memory");            /* no-clobber list */
    return res;
}

static inline int lune_atomic32_get(lune_atomic32_t *a)
{
    return *a;
}

static inline void lune_atomic32_set(lune_atomic32_t *a, int v)
{
    *a = v;
}

static inline void lune_atomic32_inc(lune_atomic32_t *a)
{
    (void)__sync_add_and_fetch(a, 1);
}

static inline int lune_atomic32_inc_and_return(lune_atomic32_t *a)
{
    return __sync_add_and_fetch(a, 1);
}

static inline void lune_atomic32_dec(lune_atomic32_t *a)
{
    (void)__sync_sub_and_fetch(a, 1);
}

static inline void lune_atomic32_add(lune_atomic32_t *a, int v)
{
    (void)__sync_add_and_fetch(a, v);
}

static inline void lune_atomic32_sub(lune_atomic32_t *a, int v)
{
    (void)__sync_sub_and_fetch(a, v);
}

static inline int lune_atomic32_dec_is_zero(lune_atomic32_t *a)
{
    return (0 == __sync_sub_and_fetch(a, 1));
}

/*
    (atomic) equivalent to:
    if (*dst == exp)
        *dst = src
    return:
        Non-zero on success; 0 on failure
*/
static inline int lune_atomic32_cmpset(lune_atomic32_t *dst, int exp, int src)
{
    char res;

    asm volatile(
            "lock;"
            "cmpxchgl %[src], %[dst];"
            "sete %[res];"
            : [res] "=a" (res),     /* output */
              [dst] "=m" (*dst)
            : [src] "r" (src),      /* input */
              "a" (exp),
              "m" (*dst)
            : "memory");            /* no-clobber list */
    return res;
}

static inline long long lune_atomic64_get(lune_atomic64_t *a)
{
    return *a;
}

static inline void lune_atomic64_set(lune_atomic64_t *a, long long v)
{
    *a = v;
}

static inline void lune_atomic64_inc(lune_atomic64_t *a)
{
    (void)__sync_add_and_fetch(a, 1);
}

static inline long long lune_atomic64_inc_and_return(lune_atomic64_t *a)
{
    return __sync_add_and_fetch(a, 1);
}

static inline void lune_atomic64_dec(lune_atomic64_t *a)
{
    (void)__sync_sub_and_fetch(a, 1);
}

static inline void lune_atomic64_add(lune_atomic64_t *a, long long v)
{
    (void)__sync_add_and_fetch(a, v);
}

static inline void lune_atomic64_sub(lune_atomic64_t *a, long long v)
{
    (void)__sync_sub_and_fetch(a, v);
}

static inline int lune_atomic64_dec_is_zero(lune_atomic64_t *a)
{
    return (0 == __sync_sub_and_fetch(a, 1));
}

/*
    (atomic) equivalent to:
    if (*dst == exp)
        *dst = src
    return:
        Non-zero on success; 0 on failure
*/
static inline int lune_atomic64_cmpset(lune_atomic64_t *dst, long long exp, long long src)
{
    char res;

    asm volatile(
            "lock;"
            "cmpxchgq %[src], %[dst];"
            "sete %[res];"
            : [res] "=a" (res),     /* output */
              [dst] "=m" (*dst)
            : [src] "r" (src),      /* input */
              "a" (exp),
              "m" (*dst)
            : "memory");            /* no-clobber list */
    return res;
}

static inline lune_atomic_ptr_t lune_atomic_ptr_get(lune_atomic_ptr_t *a)
{
    return *a;
}

static inline lune_atomic_ptr_t lune_atomic_ptr_exchange(lune_atomic_ptr_t *a,
    lune_atomic_ptr_t v)
{
    return __sync_lock_test_and_set(a, v);
}

#ifdef __cplusplus
}
#endif

#endif