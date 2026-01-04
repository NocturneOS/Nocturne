#pragma once

#include "lib/list.h"
#include "sys/scheduler/process.h"

typedef enum {
    CREATED = 0,
    RUNNING,
    PAUSED,
    DEAD
} thread_state_t;

typedef struct {
    // 0
	list_item_t		list_item;			/* List item */
    // 12
	process_t*		process;			/* This thread's process */
    // 16
	uint32_t		flags;			/* Flags*/
    // 20
	size_t			stack_size;			/* Size of thread's stack */
    // 24
	void*			stack;
    // 28
	size_t*		    esp;				/* Thread state */
    // 32
	size_t		    entry_point;
    // 36
	size_t		    id;				/* Thread ID */
    // 40
	size_t  		stack_top;
    // 44
    thread_state_t  state;
    // 48
    char*           fxsave_region;
    // 52: This is used in TSS.
    size_t          kernel_stack_top;
    // 56
    size_t          kernel_stack_bottom;
    // 60: Indicates the last system error happened in this thread (i/o error, memory allocation fail, etc.).
    size_t          last_error;
} thread_t;

// Thread runs in kernel space
#define THREAD_KERNEL (1 << 0)

// Thread won't be added into a thread list
#define THREAD_RAW (1 << 1)

void initialize_thread_list();
thread_t* get_kernel_thread();
thread_t* get_current_thread();

thread_t* _thread_create_unwrapped(process_t* proc, void* entry_point, size_t stack_size, size_t flags, size_t* args, size_t arg_count);
  
thread_t* thread_create(process_t* proc, void* entry_point, size_t stack_size, size_t flags, size_t* args, size_t arg_count);
                        
thread_t* thread_create_arg1(process_t* proc, void* entry_point, size_t stack_size, size_t flags, size_t arg1);

/* Exit from thread */
void thread_exit(thread_t* thread);

__attribute__((noreturn)) void thread_exit_entrypoint();
void initialize_idle_thread();
