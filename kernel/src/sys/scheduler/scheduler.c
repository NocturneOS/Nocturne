/**
 * @file sys/scheduler.c
 * @author Пиминов Никита (nikita.piminoff@yandex.ru), NDRAEY (pikachu_andrey@vk.com)
 * @brief Менеджер задач
 * @version 0.4.3
 * @date 2025-12-29
 * @copyright Copyright SayoriOS Team (c) 2022-2026
 */

#include <sys/scheduler/scheduler.h>
#include <lib/string.h>
#include <io/logging.h>
#include "arch/x86/mem/paging.h"
#include "arch/x86/mem/paging_common.h"
#include "mem/vmm.h"
#include "lib/math.h"
#include "sys/scheduler/thread.h"
#include "sys/sync.h"


bool scheduler_working = true;
bool multi_task = false;

list_t process_list;
uint32_t next_pid = 0;			

process_t* kernel_proc = 0;
process_t* current_proc = 0;


extern uint32_t __init_esp;
extern physical_addr_t kernel_page_directory;

extern thread_t* sched_idle_thread;

mutex_t proclist_scheduler_mutex = {.lock = false};

/**
 * @brief Initializes scheduler
 */
void init_task_manager(void){
	uint32_t esp = 0;
	__asm__ volatile("mov %%esp, %0" : "=a"(esp));

	list_init(&process_list);
	initialize_thread_list();

	/* Create kernel process */
	kernel_proc = kmalloc_common(sizeof(process_t), 4);
    memset(kernel_proc, 0, sizeof(process_t));

	kernel_proc->pid = next_pid++;
    // NOTE: Page directory address must be PHYSICAL!
	kernel_proc->page_dir = kernel_page_directory;
	kernel_proc->list_item.list = nullptr;
	kernel_proc->threads_count = 1;

	kernel_proc->name = strdynamize("kernel");
	kernel_proc->cwd = strdynamize("rd0:/");
	
	list_add(&process_list, (void*)&kernel_proc->list_item);

    extern thread_t* kernel_thread;
    extern thread_t* current_thread;
    extern size_t next_thread_id;

	/* Create kernel thread */
	kernel_thread = kmalloc_common(sizeof(thread_t), 4);
    memset(kernel_thread, 0, sizeof(thread_t));

	kernel_thread->process = kernel_proc;
	kernel_thread->list_item.list = nullptr;
	kernel_thread->id = next_thread_id++;
	kernel_thread->stack_size = DEFAULT_STACK_SIZE;
	kernel_thread->esp = (size_t*)esp;
	kernel_thread->stack_top = __init_esp;
	kernel_thread->fxsave_region = kmalloc_common(512, 16);

    kernel_thread->kernel_stack_bottom = (size_t)kmalloc_common(PAGE_SIZE * 4, PAGE_SIZE);
    kernel_thread->kernel_stack_top = kernel_thread->kernel_stack_bottom + (PAGE_SIZE * 4);

    __asm__ volatile("fxsave (%0)" :: "a"(kernel_thread->fxsave_region));

    kernel_thread->flags = THREAD_KERNEL;

    thread_add_prepared(kernel_thread);

	current_proc = kernel_proc;
	current_thread = kernel_thread;

	multi_task = true;

	initialize_idle_thread();

    qemu_ok("OK");
}

void scheduler_mode(bool on) {
	scheduler_working = on;
}

size_t create_process(void* entry_point, char* name, bool is_kernel) {
    process_t* proc = allocate_one(process_t);

	proc->pid = next_pid++;
	proc->list_item.list = nullptr;  // No nested processes
	proc->threads_count = 0;

	proc->name = strdynamize(name);

    // Inherit path
	proc->cwd = strdynamize(get_current_proc()->cwd);
    
    process_add_prepared(proc);

    thread_t* thread = _thread_create_unwrapped(proc, entry_point, DEFAULT_STACK_SIZE, is_kernel ? THREAD_KERNEL : 0, NULL, 0);

    qemu_log("PID: %d, DIR: %x; Threads: %d", proc->pid, proc->page_dir, proc->threads_count);

	thread_add_prepared(thread);

    void* virt = clone_kernel_page_directory((size_t*)proc->page_tables_virts);
    uint32_t phys = virt2phys(get_kernel_page_directory(), (virtual_addr_t) virt);

    proc->page_dir = phys;
    proc->page_dir_virt = (size_t)virt;

    qemu_log("FINISHED!");

    return proc->pid;
}

 /**
 * @brief Get current process
 *
 * @return process_t* - Current process
 */
process_t* get_current_proc(void) {
    return current_proc;
}

bool process_exists(size_t pid) {
    process_t* proc = get_current_proc();

    do {
        if(proc->pid == pid) {
            return true;
        }

        proc = (process_t*)proc->list_item.next;
    } while(proc != NULL && proc->pid != 0);

    return false;
}

void process_wait(size_t pid) {
    while(process_exists(pid)) {
        __asm__ volatile("hlt" ::: "memory");
        yield();
    }
}

bool is_multitask(void){
    return multi_task;
}

static void remove_thread(thread_t* thread) {
    process_t* process = thread->process;
    qemu_log("REMOVING DEAD THREAD: #%u", thread->id);

    thread_remove_prepared((thread_t*)thread);

    qemu_log("REMOVED FROM LIST");

    kfree(thread->fxsave_region);
    kfree((void*)thread->kernel_stack_bottom);
    kfree(thread->stack);
    kfree((void*)thread);

    qemu_log("FREED MEMORY");

    process->threads_count--;

    bool is_kernels_pid = current_proc->pid == 0;
    // NOTE: We should be in kernel process (PID 0) to free page tables and process itself.
    // TODO: Switch to kernel's PD here, because process info stored there
    if(process->threads_count == 0 && is_kernels_pid) {
        qemu_warn("PROCESS #%d `%s` DOES NOT HAVE ANY THREADS", process->pid, process->name);

        // load_page_directory(kernel_page_directory);

        if(process->program) {
            for (int32_t i = 0; i < process->program->elf_header.e_phnum; i++) {
                Elf32_Phdr *phdr = process->program->p_header + i;

                if(phdr->p_type != PT_LOAD)
                    continue;

                size_t pagecount = MAX((ALIGN(phdr->p_memsz, PAGE_SIZE) / PAGE_SIZE), 1U);

                for(size_t x = 0; x < pagecount; x++) {
                    size_t vaddr = phdr->p_vaddr + (x * PAGE_SIZE);
                    size_t paddr = virt2phys_ext((void*)process->page_dir_virt, process->page_tables_virts, vaddr);

                    qemu_log("Page dir: %x; Free: %x -> %x", process->page_dir_virt, vaddr, paddr);

                    phys_free_single_page(paddr);
                }
            }

            unload_elf(process->program);

            qemu_log("Program unloaded.");
        }

        for(size_t pt = 0; pt < 1024; pt++) {
            size_t page_table = process->page_tables_virts[pt];
            if(page_table) {
                qemu_note("[%-4d] <%08x - %08x> USED PAGE TABLE AT: %x", 
                    pt,
                    (pt * PAGE_SIZE) << 10,
                    ((pt + 1) * PAGE_SIZE) << 10,
                    page_table
                );
                kfree((void *) page_table);
            }
        }

        qemu_log("FREED PAGE TABLES");

        kfree((void *) process->page_dir_virt);

        qemu_log("FREED PAGE DIR");
        
        kfree(process->name);
        kfree(process->cwd);

        process_remove_prepared((process_t*)process);

        qemu_log("REMOVED PROCESS FROM LIST");
        kfree((void*)process);

        qemu_log("FREED PROCESS LIST ITEM");
    }
}

static inline thread_t* sched_select_next() {
    // Choose next thread.
    thread_t* next_thread = (thread_t *)get_current_thread()->list_item.next;

    while(next_thread != NULL) {
        // If the thread is PAUSED, skip it.
        if(next_thread->state == PAUSED) {
            next_thread = (thread_t *)next_thread->list_item.next;
            continue;
        }

        // If we encountered dead thread, remove it and skip.
        if(next_thread->state == DEAD) {
        	qemu_log("QUICK NOTICE: WE ARE IN PROCESS NR. #%u", current_proc->pid);

            // Select next of next process, becuase removing next process will free the resources. (Avoid use-after-free conditions).
            thread_t* next_thread_soon = (thread_t *)next_thread->list_item.next;

            remove_thread(next_thread);

            next_thread = (thread_t *)next_thread->list_item.next;
            continue;
        }

        break;
    }

    return next_thread;
}

void task_switch_v2_wrapper(registers_t* regs) {
    if(!multi_task) {
        // qemu_err("Scheduler is disabled!");
        return;
    }

    // Choose next thread.
    thread_t* next_thread = sched_select_next();

	// If no next thresd available, go idle.
    if(!next_thread) {
        qemu_note("No available threads, going to sleep...");

    	next_thread = sched_idle_thread;
    }

    // Actually switch the context.
    task_switch_v2(get_current_thread(), next_thread);

    // next_thread is now current_thread.
}

void process_add_prepared(process_t* process) {
    mutex_get(&proclist_scheduler_mutex);

    list_add(&process_list, (list_item_t*)&process->list_item);

    mutex_release(&proclist_scheduler_mutex);
}

void process_remove_prepared(process_t* process) {
    mutex_get(&proclist_scheduler_mutex);

    list_remove(&process->list_item);

    mutex_release(&proclist_scheduler_mutex);
}

void yield() {
    #ifdef NOCTURNE_X86
    __asm__ volatile("cli");

    //__asm__ volatile("int $0x80" :: "a"(SYSCALL_YIELD) : "memory");
    
    registers_t regs;

    get_regs(&regs);
    
    task_switch_v2_wrapper(&regs);

    __asm__ volatile("sti");
    #endif
}

void enter_usermode(void (*ep)()) {
    __asm__ volatile("cli \n\
        push $0x23 \n\
        push %0 \n\
        push $0x202 \n\
        push $0x1B \n\
        push %1 \n\
        iret \n\
    " :: "r"(get_current_thread()->esp), "r"((size_t)ep));

    // ep();
}
