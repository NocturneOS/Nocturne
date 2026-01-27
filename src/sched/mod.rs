use core::{
    alloc::Layout,
    arch::{asm, naked_asm},
    fmt::Write,
    sync::atomic::{AtomicUsize, Ordering},
};

use alloc::{
    collections::{linked_list::LinkedList, vec_deque::VecDeque},
    fmt::format,
    string::String,
    sync::Arc,
    vec::Vec,
};
use lazy_static::lazy_static;
use spin::{Mutex, MutexGuard};
use x86::bits32::eflags::EFlags;

use crate::{
    arch::{self, CPURegisters},
    io::logging::SerialWriter,
    qemu_log, qemu_print, qemu_println,
    sched::{
        archspec::ArchitectureSpecificRegion,
        process::Process,
        thread::{Thread, ThreadFlags},
    },
    spec::WORD_SIZE,
    time::get_uptime_ticks,
};

mod archspec;
pub mod process;
pub mod thread;

lazy_static! {
    static ref SCHEDULER: Mutex<Scheduler> = Mutex::new(Scheduler::new());
    static ref GLOBAL_PID: AtomicUsize = AtomicUsize::new(0);
    static ref GLOBAL_TID: AtomicUsize = AtomicUsize::new(0);
}

pub struct Scheduler {
    is_initialized: bool,

    process_list: LinkedList<Arc<Process>>,
    thread_list: LinkedList<Arc<Thread>>,

    working_queue: VecDeque<Arc<Thread>>,

    idle_task: Option<Arc<Thread>>,

    current_process: Option<Arc<Process>>,
    current_thread: Option<Arc<Thread>>,
}

unsafe extern "C" {
    fn __context_switch(
        this_process: &Process,
        this_thread: &Thread,
        next_process: &Process,
        next_thread: &Thread,
    );
}

fn next_pid() -> usize {
    GLOBAL_PID.fetch_add(1, Ordering::SeqCst)
}

fn next_tid() -> usize {
    GLOBAL_TID.fetch_add(1, Ordering::SeqCst)
}

impl Scheduler {
    pub const fn new() -> Self {
        Self {
            is_initialized: false,

            process_list: LinkedList::new(),
            thread_list: LinkedList::new(),

            working_queue: VecDeque::new(),

            idle_task: None,

            current_process: None,
            current_thread: None,
        }
    }

    pub fn init(&mut self) {
        let kernel_process = Process {
            id: next_pid(),

            page_directory_phys: unsafe { x86::controlregs::cr3() as _ },
            page_directory_virt: unsafe { x86::controlregs::cr3() as _ },

            thread_count: 1,

            name: String::from("krnl"),
            cwd: String::from("<unknown>"),
        };

        let kernel_process = Arc::new(kernel_process);

        let kernel_thread = Thread {
            id: next_tid(),

            process: Arc::clone(&kernel_process),
            flags: ThreadFlags::empty(),
            state: thread::ThreadState::Running,
            stack_size: 32 << 10, // 32 KB
            arch_specific_region: ArchitectureSpecificRegion::new(),
            last_error: 0,

            // Those fields will be filled automatically on context change
            stack_addr: 0,
            stack_pointer: 0,
            entry_point: 0,
        };

        let kernel_thread = Arc::new(kernel_thread);

        self.current_process = Some(Arc::clone(&kernel_process));
        self.current_thread = Some(Arc::clone(&kernel_thread));

        self.idle_task = self.create_thread(
            Arc::clone(&kernel_process),
            idle_task,
            0x100,
            ThreadFlags::Raw,
        );

        self.process_list.push_back(kernel_process);
        self.thread_list.push_back(Arc::clone(&kernel_thread));

        self.working_queue.push_back(kernel_thread);

        self.is_initialized = true;
    }

    pub fn create_thread(
        &mut self,
        process: Arc<Process>,
        entry: fn() -> (),
        stack_size: usize,
        flags: ThreadFlags,
    ) -> Option<Arc<Thread>> {
        let stack =
            unsafe { alloc::alloc::alloc_zeroed(Layout::from_size_align(stack_size, 0x1000).ok()?) };

        let id = next_tid();

        let mut writeable_esp = unsafe { stack.add(stack_size).addr() } as *mut usize;

        unsafe {
            // Entry point
            writeable_esp.sub(1).write(entry as *const () as usize);

            // EFLAGS
            writeable_esp.sub(2).write(0x202);

            // writeable_esp.sub(3).write(0x10101010);  // EAX
            // writeable_esp.sub(4).write(0x20202020);  // EBX
            // writeable_esp.sub(5).write(0x30303030);  // ECX
            // writeable_esp.sub(6).write(0x40404040);  // EDX
            // writeable_esp.sub(7).write(0x50505050);  // ESI
            // writeable_esp.sub(8).write(0x60606060);  // EDI

            // 2 is EP and EFLAGS, 7 is the register count we will save on stack on context change.
            writeable_esp = writeable_esp.sub(2 + 7);
        }

        qemu_log!("ESP: {:08x?}", writeable_esp.addr());

        let tcb = Thread {
            id,
            process,
            flags,
            state: thread::ThreadState::Ready,
            stack_addr: stack.addr(),
            stack_size,
            stack_pointer: writeable_esp.addr(),
            entry_point: entry as *const () as usize,
            arch_specific_region: ArchitectureSpecificRegion::new(),
            last_error: 0,
        };

        let tcb = Arc::new(tcb);

        self.thread_list.push_back(Arc::clone(&tcb));

        if !flags.contains(ThreadFlags::Raw) {
            self.working_queue.push_back(Arc::clone(&tcb));
        }

        qemu_log!("Added thread nr: {id}");

        Some(tcb)
    }

    fn this_task(&self) -> Arc<Thread> {
        self.current_thread.as_ref().unwrap().clone()
    }

    fn next_task(&mut self) -> Arc<Thread> {
        let task = self
            .working_queue
            .pop_front();

        if let Some(task) = task {
            return task;
        }

        qemu_log!("No tasks, idling.");

        Arc::clone(self.idle_task.as_ref().unwrap())
    }

    pub fn schedule(&mut self) {
        // qemu_log!("Entered scheduler");

        let this = self.this_task();

        if !Arc::ptr_eq(&this, self.idle_task.as_ref().unwrap()) {
            self.working_queue.push_back(Arc::clone(&this));
        }

        // qemu_log!("Deque len: {}", self.working_queue.len());

        // for i in self.working_queue.iter().map(|x| x.id) {
        //     qemu_log!("- {i}");
        // }

        let next = self.next_task();

        if this.id == next.id {
            return;
        }

        {
            let this_ref = this.as_ref();
            let this_proc = this.as_ref().process.as_ref();

            let next_ref = next.as_ref();
            let next_proc = this.as_ref().process.as_ref();

            unsafe {
                __context_switch(this_proc, this_ref, next_proc, next_ref);
            }
        }

        self.current_process = Some(Arc::clone(&next.process));
        self.current_thread = Some(next);
    }
}

fn this() -> MutexGuard<'static, Scheduler> {
    SCHEDULER.try_lock().expect("Failed to lock a scheduler!")
}

pub fn init() {
    let is_ena = arch::are_interrupts_enabled();

    arch::disable_interrupts();

    this().init();

    if is_ena {
        arch::enable_interrupts();
    }
}

fn this_process() -> Arc<Process> {
    let is_ena = arch::are_interrupts_enabled();

    arch::disable_interrupts();

    let lock = this();

    let proc = lock.current_process.as_ref().unwrap();

    let value = Arc::clone(proc);

    if is_ena {
        arch::enable_interrupts();
    }

    value
}

pub fn create_thread(entry: fn() -> (), stack_size: usize, flags: ThreadFlags) {
    let is_ena = arch::are_interrupts_enabled();

    arch::disable_interrupts();

    //

    let proc = this_process();

    this().create_thread(proc, entry, stack_size, flags);

    //

    if is_ena {
        arch::enable_interrupts();
    }
}

pub fn schedule() {
    let is_ena = arch::are_interrupts_enabled();

    arch::disable_interrupts();

    //

    if this().is_initialized {
        this().schedule();
    }

    //

    if is_ena {
        arch::enable_interrupts();
    }
}

#[inline]
pub fn yield_now() {
    schedule();
}

pub fn sleep(dur: core::time::Duration) {
    let target = crate::time::get_uptime_nanos() + dur.as_nanos();

    while crate::time::get_uptime_nanos() <= target {
        arch::halt();
    }
}

fn idle_task() {
    // let mut a = 0usize;

    loop {
        arch::halt();
        // a = a.wrapping_add(1);
    }
}
