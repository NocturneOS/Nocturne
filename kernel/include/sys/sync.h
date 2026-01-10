#pragma once

#include <stdbool.h>
#include "common.h"

typedef _Atomic(_Bool) atomic_bool;

#define ATOMIC_FLAG_INIT { 0 }

typedef struct atomic_flag { atomic_bool _Value; } atomic_flag;

#define atomic_flag_test_and_set(object) __atomic_exchange_n(&(object)->_Value, 1, __ATOMIC_SEQ_CST)
#define atomic_flag_clear(object) __atomic_store_n(&(object)->_Value, 0, __ATOMIC_SEQ_CST)

/* Get spinlock */
void spinlock_get(atomic_flag* spinlock);

/* Release spinlock */
void spinlock_release(atomic_flag* spinlock);

SAYORI_INLINE bool spinlock_is_locked(atomic_flag* spinlock) {
    return (bool)spinlock->_Value;
}