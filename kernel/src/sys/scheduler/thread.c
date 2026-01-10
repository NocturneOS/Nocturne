#include "sys/scheduler/thread.h"
#include "sys/scheduler/scheduler.h"
#include "io/logging.h"

list_t thread_list;
uint32_t next_thread_id = 0;	

thread_t* kernel_thread = 0;
thread_t* current_thread = 0;

atomic_flag threadlist_scheduler_mutex = ATOMIC_FLAG_INIT;

thread_t* sched_idle_thread;

void initialize_thread_list() {
    list_init(&thread_list);
}

thread_t* get_kernel_thread() {
    return kernel_thread;
}

thread_t* get_current_thread() {
    return current_thread;
}

void thread_add_prepared(thread_t* thread) {
    spinlock_get(&threadlist_scheduler_mutex);

    list_add(&thread_list, (list_item_t*)&thread->list_item);

    spinlock_release(&threadlist_scheduler_mutex);
}

void thread_remove_prepared(thread_t* thread) {
    spinlock_get(&threadlist_scheduler_mutex);

    list_remove(&thread->list_item);

    spinlock_release(&threadlist_scheduler_mutex);
}

/**
 * @brief Создание потока
 * 
 * @param proc - Процесс
 * @param entry_point - Точка входа
 * @param stack_size - Размер стека
 * @param kernel - Функция ядра?
 *
 * @return thread_t* - Поток
 */
 thread_t* _thread_create_unwrapped(process_t* proc, void* entry_point, size_t stack_size, size_t flags, size_t* args, size_t arg_count) {
    if(!is_multitask()) {
        qemu_err("Scheduler is disabled!");
        return NULL;
    }

    qemu_log("Process at: %p", proc);
    qemu_log("Stack size: %d", stack_size);
    qemu_log("Entry point: %p", entry_point);
    qemu_log(
        "Flags: %08x [%c]", 
        flags,
        (flags & THREAD_KERNEL) ? 'K' : '-'
    );

    /* Create new thread handler */
    thread_t* tmp_thread = kmalloc_common(sizeof(thread_t), 4);
    memset(tmp_thread, 0, sizeof(thread_t));

    /* Initialization of thread  */
    tmp_thread->id = next_thread_id++;
    tmp_thread->list_item.list = nullptr;
    tmp_thread->process = proc;
    tmp_thread->stack_size = stack_size;
    tmp_thread->entry_point = (uint32_t) entry_point;
	tmp_thread->fxsave_region = kmalloc_common(512, 16);
    tmp_thread->flags = flags;

    tmp_thread->kernel_stack_bottom = (size_t)kmalloc_common(PAGE_SIZE, 16);
    tmp_thread->kernel_stack_top = tmp_thread->kernel_stack_bottom + PAGE_SIZE;

    qemu_log("Kernel stack for thread: %08x (Top: %08x)", tmp_thread->kernel_stack_bottom, tmp_thread->kernel_stack_top);

    /* Create thread's stack */
    size_t real_stack_size = ALIGN(stack_size, PAGE_SIZE);

    // FIXME: Remove `+ PAGE_SIZE` and you'll get undefined behaviour (the first page table will be 0, but should always be mapped).
    // Something overwrites the PD[0] in user mode.
    size_t* stack = kmalloc_common(real_stack_size + PAGE_SIZE, PAGE_SIZE);
    memset(stack, 0, real_stack_size);

    qemu_log("Stack at: %p (Top: %x)", stack, (size_t)stack + real_stack_size);

    // If this task is a user task, make stack user-space.
    // So, this is why our stack is page-aligned by its size and position.
    if((flags & THREAD_KERNEL) == 0) {
        size_t* pd = get_kernel_page_directory();

        for(size_t i = 0; i < real_stack_size; i += PAGE_SIZE) {
            phys_set_flags(pd, ((size_t)stack) + i, PAGE_WRITEABLE | PAGE_USER);
        }
    }

    tmp_thread->stack = stack;
    tmp_thread->stack_top = (uint32_t) stack + stack_size;

    /* Thread's count increment */
    proc->threads_count++;

    /* Fill stack */

    /* Create pointer to stack frame */
    tmp_thread->esp = (size_t*)((size_t)stack + stack_size);

    if(args != NULL) {
        for(size_t i = 0; i < arg_count; i++) {
            *--tmp_thread->esp = (size_t)args[i];
        }
    }

    // Fill the stack.
    // On normal systems (like in Linux) exit is called manually, but if something goes wrong, give this task a peaceful death.

    // Add exit entrypoint. But it will be called only in Kernel Task.
    // Any invocation of kernel code in usermode is painful for program (and me).
    *--tmp_thread->esp = (uint32_t)thread_exit_entrypoint;

    *--tmp_thread->esp = (uint32_t)entry_point;

    // If it's a user task, load up the user_mode jumper.
    // TODO: To enable usermode tasks, uncomment those 4 lines below.

    // if((flags & THREAD_KERNEL) == 0) {
    //     *--tmp_thread->esp = (uint32_t)0;
    //     *--tmp_thread->esp = (uint32_t)enter_usermode;
    // }

    *--tmp_thread->esp = 0x202;   // Our eflags

    // 7 is a register count we saving on the stack on the task switch.
    // See src/arch/x86/asm/switch_task.s for more info.
    tmp_thread->esp -= 7;

    tmp_thread->state = PAUSED;

    /* Add thread to ring queue (if not raw) */
    if(~flags & THREAD_RAW) {
        thread_add_prepared(tmp_thread);
    }

    return tmp_thread;
}

thread_t* thread_create(process_t* proc, void* entry_point, size_t stack_size, size_t flags, size_t* args, size_t arg_count) {
    if(!is_multitask()) {
        qemu_err("Scheduler is disabled!");
        return NULL;
    }

    /* Disable all interrupts */
    __asm__ volatile ("cli");

    /* Create new thread handler */
    thread_t* tmp_thread = (thread_t*) _thread_create_unwrapped(proc, entry_point, stack_size, flags, args, arg_count);

    tmp_thread->state = CREATED;

    /* Enable all interrupts */
    __asm__ volatile ("sti");

    qemu_ok("CREATED THREAD");

    return tmp_thread;
}

thread_t* thread_create_arg1(process_t* proc, void* entry_point, size_t stack_size, size_t flags, size_t arg1) {
    if(!is_multitask()) {
        qemu_err("Scheduler is disabled!");
        return NULL;
    }

    __asm__ volatile ("cli");

    thread_t* tmp_thread = (thread_t*) _thread_create_unwrapped(proc, entry_point, stack_size, flags, &arg1, 1);

    tmp_thread->state = CREATED;

    __asm__ volatile ("sti");

    qemu_ok("CREATED THREAD");

    return tmp_thread;
}

void thread_exit(thread_t* thread){
	if(!is_multitask()) {
        qemu_err("Scheduler is disabled!");
        return;
    }

	/* Mark it as dead */
    thread->state = DEAD;

	/* Load to ECX switch function address */
	__asm__ volatile ("mov %0, %%ecx"::"a"(&task_switch_v2_wrapper));

	/* Jump to switch_task() */
	__asm__ volatile ("call *%ecx");
}

__attribute__((noreturn)) void thread_exit_entrypoint() {
    qemu_note("THREAD %d WANTS TO EXIT!", current_thread->id);
    
    thread_exit(current_thread);

    while(1)  // If something goes wrong, we loop here.
        __asm__ volatile("hlt");
}

__attribute__((noreturn)) void sched_idle_task() {
	while(1) {
		__asm__ volatile("hlt");
	}
}

void initialize_idle_thread() {
	sched_idle_thread = thread_create(
		get_current_proc(),
		sched_idle_task,
		0x100,
		THREAD_KERNEL | THREAD_RAW,
		NULL,
		0
	);
}
