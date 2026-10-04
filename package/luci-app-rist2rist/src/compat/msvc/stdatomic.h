/*
 * Copyright © 2018, VideoLAN and dav1d authors
 * Copyright © 2020, VideoLAN and librist authors
 * Copyright © 2019-2020 SipRadius LLC
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef MSCVER_STDATOMIC_H_
#define MSCVER_STDATOMIC_H_

#if !defined(__cplusplus) && defined(_MSC_VER)

#pragma warning(push)
#pragma warning(disable:4067)    /* newline for __has_include_next */

#if defined(__clang__) && __has_include_next(<stdatomic.h>)
   /* use the clang stdatomic.h with clang-cl*/
#  include_next <stdatomic.h>
#else /* ! stdatomic.h */

#include <windows.h>

#include <stddef.h>
#include <stdint.h>

typedef volatile ULONG  __declspec(align(32)) atomic_bool;
typedef volatile ULONG  __declspec(align(32)) atomic_int;
typedef volatile ULONG __declspec(align(32)) atomic_uint;
typedef volatile ULONG __declspec(align(32)) atomic_ulong;
typedef volatile USHORT __declspec(align(16)) atomic_uint_fast16_t;
typedef volatile ULONG64 __declspec(align(32)) atomic_uint_fast64_t;

typedef enum {
    memory_order_relaxed,
    memory_order_acquire,
    memory_order_release
} msvc_atomic_memory_order;

#define atomic_init(p_a, v)           atomic_store(p_a, v)

static inline ULONG atomic_load_32(volatile ULONG *p_a)
{
    return (ULONG)InterlockedCompareExchange((LONG volatile *)p_a, 0, 0);
}

static inline ULONG64 atomic_load_64(volatile ULONG64 *p_a)
{
    return (ULONG64)InterlockedCompareExchange64((LONG64 volatile *)p_a, 0, 0);
}

#define atomic_load(p_a) \
    (sizeof(*(p_a)) == 8 ? \
        (uint64_t)atomic_load_64((volatile ULONG64 *)(p_a)) : \
        (uint64_t)atomic_load_32((volatile ULONG *)(p_a)))

static inline void atomic_store_32(volatile ULONG *p_a, ULONG v)
{
    InterlockedExchange((LONG volatile *)p_a, (LONG)v);
}

static inline void atomic_store_64(volatile ULONG64 *p_a, ULONG64 v)
{
    InterlockedExchange64((LONG64 volatile *)p_a, (LONG64)v);
}

#define atomic_store(p_a, v) \
    do { \
        if (sizeof(*(p_a)) == 8) \
            atomic_store_64((volatile ULONG64 *)(p_a), (ULONG64)(v)); \
        else \
            atomic_store_32((volatile ULONG *)(p_a), (ULONG)(v)); \
    } while (0)

#define atomic_load_explicit(p_a, mo) atomic_load(p_a)
#define atomic_store_explicit(p_a, v, mo) atomic_store(p_a, v)

static inline ULONG atomic_fetch_add_32(volatile ULONG *p_a, ULONG inc)
{
    return (ULONG)InterlockedExchangeAdd((LONG volatile *)p_a, (LONG)inc);
}

static inline ULONG64 atomic_fetch_add_64(volatile ULONG64 *p_a, ULONG64 inc)
{
    return (ULONG64)InterlockedExchangeAdd64((LONG64 volatile *)p_a, (LONG64)inc);
}

#define atomic_fetch_add(p_a, inc) \
    (sizeof(*(p_a)) == 8 ? \
        (uint64_t)atomic_fetch_add_64((volatile ULONG64 *)(p_a), (ULONG64)(inc)) : \
        (uint64_t)atomic_fetch_add_32((volatile ULONG *)(p_a), (ULONG)(inc)))

static inline ULONG atomic_fetch_sub_32(volatile ULONG *p_a, ULONG dec)
{
    return (ULONG)InterlockedExchangeAdd((LONG volatile *)p_a, -(LONG)dec);
}

static inline ULONG64 atomic_fetch_sub_64(volatile ULONG64 *p_a, ULONG64 dec)
{
    return (ULONG64)InterlockedExchangeAdd64((LONG64 volatile *)p_a, -(LONG64)dec);
}

#define atomic_fetch_sub(p_a, dec) \
    (sizeof(*(p_a)) == 8 ? \
        (uint64_t)atomic_fetch_sub_64((volatile ULONG64 *)(p_a), (ULONG64)(dec)) : \
        (uint64_t)atomic_fetch_sub_32((volatile ULONG *)(p_a), (ULONG)(dec)))

#define atomic_fetch_add_explicit(p_a, inc, mo)   atomic_fetch_add(p_a, inc)
#define atomic_fetch_sub_explicit(p_a, inc, mo)   atomic_fetch_sub(p_a, inc)

static inline int atomic_compare_exchange_weak_32(volatile ULONG *obj, ULONG *expected, ULONG desired)
{
    ULONG old = *expected;
    *expected = (ULONG)InterlockedCompareExchange((LONG volatile *)obj, (LONG)desired, (LONG)old);
    return old == *expected;
}

static inline int atomic_compare_exchange_weak_64(volatile ULONG64 *obj, ULONG64 *expected, ULONG64 desired)
{
    ULONG64 old = *expected;
    *expected = (ULONG64)InterlockedCompareExchange64((LONG64 volatile *)obj, (LONG64)desired, (LONG64)old);
    return old == *expected;
}

#define atomic_compare_exchange_weak(obj, expected, desired) \
    (sizeof(*(obj)) == 8 ? \
        atomic_compare_exchange_weak_64((volatile ULONG64 *)(obj), (ULONG64 *)(expected), (ULONG64)(desired)) : \
        atomic_compare_exchange_weak_32((volatile ULONG *)(obj), (ULONG *)(expected), (ULONG)(desired)))

#endif /* ! stdatomic.h */

#pragma warning(pop)

#endif /* !defined(__cplusplus) && defined(_MSC_VER) */

#endif /* MSCVER_STDATOMIC_H_ */
