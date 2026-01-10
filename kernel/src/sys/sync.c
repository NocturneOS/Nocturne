/**
 * @file sys/sync.c
 * @author NDRAEY (pikachu_andrey@vk.com)
 * @brief Synchronization primitives
 * @version 0.4.3
 * @date 2022-10-01
 * @copyright Copyright SayoriOS Team (c) 2022-2026
 */
 
#include	"sys/sync.h"

// https://github.com/dreamportdev/Osdev-Notes/blob/master/05_Scheduling/04_Locks.md
// https://wiki.osdev.org/Synchronization_Primitives#Spinlocks

void spinlock_get(atomic_flag* spinlock) {
    while (atomic_flag_test_and_set(spinlock)) {
        __builtin_ia32_pause();
    }
}

void spinlock_release(atomic_flag* spinlock) {
    atomic_flag_clear(spinlock);
}