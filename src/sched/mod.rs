use core::{
    alloc::Layout,
    sync::atomic::{AtomicUsize, Ordering},
};

use alloc::{
    collections::{linked_list::LinkedList, vec_deque::VecDeque},
    string::String,
    sync::Arc,
};
use lazy_static::lazy_static;
use spin::{Mutex, MutexGuard};

use crate::{
    arch,
    qemu_log,
    sched::{
        archspec::ArchitectureSpecificRegion,
        process::Process,
        thread::{Thread, ThreadFlags},
    },
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
    pub is_initialized: bool,

    process_list: LinkedList<Arc<Process>>,
    thread_list: LinkedList<Arc<Thread>>,

    working_queue: VecDeque<Arc<Thread>>,

    idle_task: Option<Arc<Thread>>,

    current_process: Option<Arc<Process>>,
    current_thread: Option<Arc<Thread>>,
}

unsafe extern "C" {
    pub unsafe fn __context_switch(
        this_process: *const Process,
        this_thread: *mut Thread,
        next_process: *const Process,
        next_thread: *const Thread,
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
            0x1000,
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
        let stack: *mut u8 =
            unsafe { alloc::alloc::alloc_zeroed(Layout::from_size_align(stack_size, 0x1000).ok()?) };

        let id = next_tid();

        let mut writeable_sp = unsafe { stack.addr() + stack_size } as *mut usize;

        #[cfg(target_arch = "x86")]
        unsafe {
            writeable_sp = writeable_sp.sub(1);
            writeable_sp.write(entry as *const () as usize);
            
            writeable_sp = writeable_sp.sub(1);
            writeable_sp.write(0x202);  // IF=1, IOPL=0
           
            writeable_sp = writeable_sp.sub(1);
            writeable_sp.write(0);  // RAX/EAX
            writeable_sp = writeable_sp.sub(1);
            writeable_sp.write(0);  // RBX/EBX
            writeable_sp = writeable_sp.sub(1);
            writeable_sp.write(0);  // RCX/ECX
            writeable_sp = writeable_sp.sub(1);
            writeable_sp.write(0);  // RDX/EDX
            writeable_sp = writeable_sp.sub(1);
            writeable_sp.write(0);  // RSI/ESI
            writeable_sp = writeable_sp.sub(1);
            writeable_sp.write(0);  // RDI/EDI
            writeable_sp = writeable_sp.sub(1);
            writeable_sp.write(0);  // RBP/EBP
        }

        #[cfg(target_arch = "x86_64")]
        unsafe {
            writeable_sp = writeable_sp.sub(1);
            writeable_sp.write(entry as *const () as usize);
            
            writeable_sp = writeable_sp.sub(1);
            writeable_sp.write(0x202);  // IF=1, IOPL=0
           
            writeable_sp = writeable_sp.sub(1);
            writeable_sp.write(0);  // RAX
            writeable_sp = writeable_sp.sub(1);
            writeable_sp.write(0);  // RBX
            writeable_sp = writeable_sp.sub(1);
            writeable_sp.write(0);  // RCX
            writeable_sp = writeable_sp.sub(1);
            writeable_sp.write(0);  // RDX
            writeable_sp = writeable_sp.sub(1);
            writeable_sp.write(0);  // RSI
            writeable_sp = writeable_sp.sub(1);
            writeable_sp.write(0);  // RDI
            writeable_sp = writeable_sp.sub(1);
            writeable_sp.write(0);  // RBP
            writeable_sp = writeable_sp.sub(1);
            writeable_sp.write(0);  // R8
            writeable_sp = writeable_sp.sub(1);
            writeable_sp.write(0);  // R9
            writeable_sp = writeable_sp.sub(1);
            writeable_sp.write(0);  // R10
            writeable_sp = writeable_sp.sub(1);
            writeable_sp.write(0);  // R11
            writeable_sp = writeable_sp.sub(1);
            writeable_sp.write(0);  // R12
            writeable_sp = writeable_sp.sub(1);
            writeable_sp.write(0);  // R13
            writeable_sp = writeable_sp.sub(1);
            writeable_sp.write(0);  // R14
            writeable_sp = writeable_sp.sub(1);
            writeable_sp.write(0);  // R15
        }

        qemu_log!("ESP: {:08x?}", writeable_sp.addr());

        let tcb = Thread {
            id,
            process,
            flags,
            state: thread::ThreadState::Ready,
            stack_addr: stack.addr(),
            stack_size,
            stack_pointer: writeable_sp.addr(),
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

    pub unsafe extern "C" fn schedule(&mut self) {
        // qemu_log!("Entered scheduler");

        let this = self.this_task();

        // If it's not an idle task, push it to the queue.
        if !Arc::ptr_eq(&this, self.idle_task.as_ref().unwrap()) {
            self.working_queue.push_back(Arc::clone(&this));
        }

        let next = self.next_task();

        // If next task is a current task, do not switch contexts.
        if this.id == next.id {
            return;
        }

        {
            let this_ref = this.as_ref();
            let this_proc = this.as_ref().process.as_ref();

            let next_ref = next.as_ref();
            let next_proc = this.as_ref().process.as_ref();

            self.current_process = Some(Arc::clone(&next.process));
            self.current_thread = Some(Arc::clone(&next));

            unsafe {
                let tp_ptr = this_proc as *const Process;
                let tt_ptr = this_ref as *const Thread;
                let np_ptr = next_proc as *const Process;
                let nt_ptr = next_ref as *const Thread;

                __context_switch(tp_ptr, tt_ptr as *mut Thread, np_ptr, nt_ptr);
            }
        }
    }
}

pub fn this() -> MutexGuard<'static, Scheduler> {
    // unsafe { SCHEDULER.get_mut() }
    SCHEDULER.try_lock().expect("Failed to lock a scheduler!")
}

pub fn init() {
    qemu_log!("-- init");

    let is_ena = arch::are_interrupts_enabled();

    arch::disable_interrupts();

    {
        this().init();
    }

    if is_ena {
        arch::enable_interrupts();
    }

    qemu_log!("-- finished");
}

fn this_process_unlocked() -> Arc<Process> {
    let lock = this();

    let proc = lock.current_process.as_ref().unwrap();

    Arc::clone(proc)
}

fn this_process() -> Arc<Process> {
    let is_ena = arch::are_interrupts_enabled();

    arch::disable_interrupts();

    let value = this_process_unlocked();

    if is_ena {
        arch::enable_interrupts();
    }

    value
}

pub fn create_thread(entry: fn() -> (), stack_size: usize, flags: ThreadFlags) {
    let is_ena = arch::are_interrupts_enabled();

    arch::disable_interrupts();

    //

    {
        let proc = this_process_unlocked();
        let mut binding = this();

        binding.create_thread(proc, entry, stack_size, flags);
    }

    //

    if is_ena {
        arch::enable_interrupts();
    }
}

pub extern "C" fn schedule() {
    let is_ena = arch::are_interrupts_enabled();

    arch::disable_interrupts();

    //

    {
        unsafe { SCHEDULER.force_unlock() };

        let mut binding = this();

        if binding.is_initialized {
            unsafe { binding.schedule() };
        }
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
