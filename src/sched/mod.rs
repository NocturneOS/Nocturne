use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use alloc::{
    collections::{linked_list::LinkedList, vec_deque::VecDeque},
    sync::Arc,
};
use lazy_static::lazy_static;
use noct_spec::KERNEL_BASE;
use noct_tools::interrupt_locker::InterruptLocker;
use spin::{Mutex, MutexGuard};

use noct_logger::qemu_log;

use self::{
    archspec::ArchitectureSpecificRegion,
    process::Process,
    stack_manager::ThreadStack,
    thread::{Thread, ThreadFlags, ThreadPriority, ThreadState},
};

mod archspec;
pub mod process;
mod stack_manager;
pub mod thread;

pub const KERNEL_THREAD_DEFAULT_STACK_SIZE: usize = 64 << 10; // 64 KB

lazy_static! {
    static ref IS_SCHEDULER_INITIALIZED: AtomicBool = AtomicBool::default();
    static ref SCHEDULER: Mutex<Scheduler> = Mutex::new(Scheduler::new());
    static ref GLOBAL_TID: AtomicUsize = AtomicUsize::new(0);
}

pub type SharedProcess = Arc<Process>;
pub type SharedThread = Arc<Thread>;

pub struct Scheduler {
    process_list: LinkedList<SharedProcess>,
    thread_list: LinkedList<SharedThread>,

    working_queue: LinkedList<SharedThread>,
    sleeping_queue: VecDeque<(SharedThread, u128)>,
    dead_queue: LinkedList<SharedThread>,

    idle_task: Option<SharedThread>,

    current_process: Option<SharedProcess>,
    current_thread: Option<SharedThread>,

    kernel_process: Option<SharedProcess>,
}

unsafe extern "C" {
    #[allow(improper_ctypes)]
    pub unsafe fn __context_switch(
        this_process: *const Process,
        this_thread: *mut Thread,
        next_process: *const Process,
        next_thread: *const Thread,
    );
}

fn next_tid() -> usize {
    GLOBAL_TID.fetch_add(1, Ordering::SeqCst)
}

impl Scheduler {
    pub const fn new() -> Self {
        Self {
            process_list: LinkedList::new(),
            thread_list: LinkedList::new(),

            working_queue: LinkedList::new(),
            sleeping_queue: VecDeque::new(),
            dead_queue: LinkedList::new(),

            idle_task: None,

            current_process: None,
            current_thread: None,

            kernel_process: None,
        }
    }

    pub fn init(&mut self) {
        let cr3 = unsafe { x86::controlregs::cr3() as _ };

        let kernel_process = Process::with_predefined_page_roots(cr3, "kernel", "");

        let kernel_process = Arc::new(kernel_process);

        self.kernel_process = Some(Arc::clone(&kernel_process));

        let arch_specific_region =
            ArchitectureSpecificRegion::with_tss_stack(noct_cpu::tss::get_tss_stack_addr());

        let kernel_thread = Thread {
            id: next_tid(),

            process: Arc::clone(&kernel_process), //Arc::into_raw(Arc::clone(&kernel_process)).into(),
            flags: ThreadFlags::empty(),
            state: (thread::ThreadState::Running as usize).into(),
            stack: ThreadStack::from_existing(
                core::ptr::null_mut(),
                64 << 10,
                core::ptr::null_mut(),
            ), // 64 KB
            arch_specific_region,

            priority: thread::ThreadPriority::Low,
            time_quantum: 1.into(),
            last_error: 0.into(),

            // Those fields will be filled automatically on context change
            entry_point: 0,
        };

        let kernel_thread = Arc::new(kernel_thread);

        self.current_process = Some(Arc::clone(&kernel_process));
        self.current_thread = Some(Arc::clone(&kernel_thread));

        self.idle_task = self.create_thread(
            Arc::clone(&kernel_process),
            idle_task,
            0x1000,
            ThreadPriority::Low,
            ThreadFlags::Raw,
        );

        self.process_list.push_back(kernel_process);
        self.thread_list.push_back(Arc::clone(&kernel_thread));

        self.working_queue.push_back(kernel_thread);

        IS_SCHEDULER_INITIALIZED.store(true, Ordering::SeqCst);
    }

    pub fn kernel_process(&self) -> &SharedProcess {
        self.kernel_process.as_ref().unwrap()
    }

    pub fn create_process(&mut self, name: &str, cwd: &str) -> SharedProcess {
        let proc = Process::new(name, cwd);

        Arc::new(proc)
    }

    pub fn create_thread(
        &mut self,
        process: SharedProcess,
        entry: fn() -> (),
        stack_size: usize,
        priority: ThreadPriority,
        flags: ThreadFlags,
    ) -> Option<SharedThread> {
        let is_user_proc = process.id != 0;

        let mut stack = if is_user_proc {
            ThreadStack::new_user(unsafe { process.address_space.get_mut() }, stack_size)
        } else {
            ThreadStack::new(stack_size)
        };

        qemu_log!("Stack allocated: base @ {:#x?}", stack.stack_addr);

        let stack_top = stack.stack_pointer;

        let id = next_tid();
        let archspec = ArchitectureSpecificRegion::new();

        //let kst = archspec.tss_kernel_stack.load(Ordering::Relaxed);

        #[cfg(target_arch = "x86")]
        unsafe {
            stack.push(
                process.address_space.get_mut(),
                thread_exit as *const () as usize,
            );

            if is_user_proc {
                stack.push(
                    process.address_space.get_mut(),
                    thread_trampoline_usermode as *const () as usize,
                );
            } else {
                stack.push(
                    process.address_space.get_mut(),
                    thread_trampoline as *const () as usize,
                );
            }

            stack.push(process.address_space.get_mut(), 0x202); // IF=1, IOPL=0

            stack.push(process.address_space.get_mut(), stack_top as usize); // EAX
            stack.push(process.address_space.get_mut(), entry as *const () as usize); // EBX
            stack.push(process.address_space.get_mut(), 0); // ECX
            stack.push(process.address_space.get_mut(), 0); // EDX
            stack.push(process.address_space.get_mut(), 0); // ESI
            stack.push(process.address_space.get_mut(), 0); // EDI
            stack.push(process.address_space.get_mut(), 0); // EBP
        }

        #[cfg(target_arch = "x86_64")]
        unsafe {
            stack.push(process.address_space.get_mut(), 0);

            if is_user_proc {
                todo!("Usermode trampoline for x86_64")
                // stack.push(process.address_space.get_mut(), thread_trampoline_usermode64 as *const () as usize);
            } else {
                stack.push(
                    process.address_space.get_mut(),
                    thread_trampoline64 as *const () as usize,
                );
            }

            stack.push(process.address_space.get_mut(), 0x202); // IF=1, IOPL=0

            stack.push(process.address_space.get_mut(), 0); // RAX
            stack.push(process.address_space.get_mut(), entry as *const () as usize); // RBX = entry
            stack.push(process.address_space.get_mut(), 0); // RCX
            stack.push(process.address_space.get_mut(), 0); // RDX
            stack.push(process.address_space.get_mut(), 0); // RSI
            stack.push(process.address_space.get_mut(), 0); // RDI
            stack.push(process.address_space.get_mut(), 0); // RBP
            stack.push(process.address_space.get_mut(), 0); // R8
            stack.push(process.address_space.get_mut(), 0); // R9
            stack.push(process.address_space.get_mut(), 0); // R10
            stack.push(process.address_space.get_mut(), 0); // R11
            stack.push(process.address_space.get_mut(), 0); // R12
            stack.push(process.address_space.get_mut(), 0); // R13
            stack.push(process.address_space.get_mut(), 0); // R14
            stack.push(process.address_space.get_mut(), 0); // R15
        }

        // qemu_log!("STACK: {:08x?}; ESP: {:08x?}", stack.addr(), writeable_sp.addr());

        process.thread_count.fetch_add(1, Ordering::SeqCst);

        let tcb = Thread {
            id,
            process: Arc::clone(&process),
            flags,
            state: (thread::ThreadState::Ready as usize).into(),
            stack,
            entry_point: entry as *const () as usize,
            arch_specific_region: archspec,
            last_error: 0.into(),
            time_quantum: priority.to_ticks().into(),
            priority,
        };

        let tcb = Arc::new(tcb);

        self.thread_list.push_back(Arc::clone(&tcb));

        if !flags.contains(ThreadFlags::Raw) {
            self.working_queue.push_back(Arc::clone(&tcb));
        }

        qemu_log!("Added thread nr: {id}");
        Some(tcb)
    }

    fn remove_task(&mut self, thread: SharedThread) {
        // If thread is placed in userspace AddrSpace.
        if unsafe { thread.stack.pointer().addr() } < KERNEL_BASE {
            let address_space = &thread.process.address_space;
            let stack_addr = thread.stack.stack_addr;

            // Count guard page in.
            let addr = stack_addr - noct_mem::paging::PAGE_SIZE;

            unsafe {
                address_space
                    .get_mut()
                    .unmap_pages(stack_addr, thread.stack.stack_size)
            };
            unsafe { address_space.get_mut().free_virt_region(addr) };

            // todo!("Free user thread's stack!");
        }

        // Remove the thread from the thread list.
        self.thread_list
            .extract_if(|x| x.id == thread.id)
            .for_each(drop);

        // The most important thing - when we are creating an Arc, its `strong_count` is 1.
        // When we call `Arc::clone` it increments.
        // In most places in the scheduler we call that method to clone the reference to threads.
        // So when we're cleaning up the thread, we have to verify that no redundant references remain
        // to avoid UB (because we free the thread's stack).
        debug_assert_eq!(Arc::strong_count(&thread), 1);

        // qemu_log!("Strong count: {:?}", Arc::strong_count(&thread));

        (*thread.process)
            .thread_count
            .fetch_sub(1, Ordering::SeqCst);

        drop(thread);
    }

    #[inline(always)]
    fn this_task(&self) -> &SharedThread {
        self.current_thread.as_ref().unwrap()
    }

    /// Puts current thread into sleep state.
    fn sleep_this(&mut self, wakeup_time_ticks: u128) {
        self.current_thread
            .as_ref()
            .unwrap()
            .state
            .store(ThreadState::Sleeping as usize, Ordering::SeqCst);

        self.working_queue
            .retain(|x| x.id != self.current_thread.as_ref().unwrap().id);

        self.sleeping_queue
            .push_back((Arc::clone(self.this_task()), wakeup_time_ticks));

        self.schedule();
    }

    #[inline(always)]
    fn check_dead_tasks(&mut self) {
        while let Some(task) = self.dead_queue.pop_front() {
            self.remove_task(task);
        }
    }

    fn check_sleeping_tasks(&mut self) {
        if self.sleeping_queue.is_empty() {
            return;
        }

        let mut index = 0;
        let mut len = self.sleeping_queue.len();

        while index < len {
            let (task, wakeup_time) = &self.sleeping_queue[index];

            if noct_time::systemclock::get_uptime_ticks() > *wakeup_time {
                task.state
                    .store(ThreadState::Ready as usize, Ordering::SeqCst);

                self.working_queue.push_front(Arc::clone(task));

                self.sleeping_queue.remove(index);

                len -= 1;

                continue;
            }

            index += 1;
        }
    }

    fn next_task(&mut self) -> SharedThread {
        let current_id = self.this_task().id;

        // If we are scheduling from a kernel task, do all dirty work to prevent use-after-free.
        if current_id == 0 {
            self.check_dead_tasks();
        }

        self.check_sleeping_tasks();

        let mut task: Option<SharedThread> = None;

        while let Some(t) = self.working_queue.pop_front() {
            let thread_state: thread::ThreadState =
                thread::ThreadState::from(t.state.load(Ordering::Relaxed));

            debug_assert!(
                thread_state != ThreadState::Dead,
                "Found a dead task in the working queue!"
            );
            debug_assert!(
                thread_state != ThreadState::Sleeping,
                "Found a sleeping task in the working queue!"
            );

            if thread_state == ThreadState::Sleeping {
                continue;
            }

            task = Some(t);
            break;
        }

        if let Some(task) = task {
            return task;
        }

        // qemu_log!("No tasks, idling.");

        Arc::clone(self.idle_task.as_ref().unwrap())
    }

    pub extern "C" fn schedule(&mut self) {
        // qemu_log!("Entered scheduler");

        let this = Arc::clone(self.this_task());

        // FIXME: We can encounter time skew under heavy loads,
        // I mean if we have 128 threads running at the same time without sleeping,
        // and we have one thread that sleeps every 500 ms, it will be woken up in 800-950 ms,
        // having almost X2 ERROR!
        //
        // Solution is maybe to check for sleeping threads here, and switch to them (if wait time
        // expires) no matter how much current task's quantum remaining.

        // If it's not an idle task, check it.
        if !Arc::ptr_eq(&this, self.idle_task.as_ref().unwrap()) {
            let state = thread::ThreadState::from(this.state.load(Ordering::Relaxed));

            // If it's running or ready, push it to the queue.
            if state == ThreadState::Ready || state == ThreadState::Running {
                // If we DIDN'T ran out of quantum, decrement and continue.
                if this.time_quantum.load(Ordering::Relaxed) != 0 {
                    this.time_quantum.fetch_sub(1, Ordering::SeqCst);
                    return;
                }

                // Reload ammo.
                this.time_quantum
                    .store(this.priority.to_ticks().into(), Ordering::SeqCst);

                this.state.store(ThreadState::Ready as _, Ordering::SeqCst);

                self.working_queue.push_back(Arc::clone(&this));
            }
        }

        let next = self.next_task();

        this.state
            .store(ThreadState::Running as _, Ordering::SeqCst);

        // If next task is a current task, do not switch contexts.
        if this.id == next.id {
            return;
        }

        {
            let this_ref = this.as_ref();
            let this_proc = this_ref.process.as_ref();

            let next_ref = next.as_ref();
            let next_proc = next_ref.process.as_ref();

            {
                self.current_process = Some(Arc::clone(&next_ref.process));
                self.current_thread = Some(Arc::clone(&next));
            }

            unsafe {
                let tp_ptr = this_proc as *const Process;
                let tt_ptr = this_ref as *const Thread;
                let np_ptr = next_proc as *const Process;
                let nt_ptr = next_ref as *const Thread;

                drop(this);
                drop(next);

                __context_switch(tp_ptr, tt_ptr as *mut Thread, np_ptr, nt_ptr);
            }
        }
    }
}

pub fn is_intiialized() -> bool {
    IS_SCHEDULER_INITIALIZED.load(Ordering::SeqCst)
}

pub fn this() -> MutexGuard<'static, Scheduler> {
    // unsafe { SCHEDULER.get_mut() }
    SCHEDULER.try_lock().expect("Failed to lock a scheduler!")
}

pub fn init() {
    qemu_log!("-- init");

    let il = InterruptLocker::lock();

    {
        this().init();
    }

    drop(il);

    qemu_log!("-- finished");
}

fn this_process_unlocked() -> SharedProcess {
    let lock = this();

    let proc = lock.current_process.as_ref().unwrap();

    Arc::clone(proc)
}

pub fn this_process() -> SharedProcess {
    let il = InterruptLocker::lock();

    let value = this_process_unlocked();

    drop(il);

    value
}

pub fn create_process(name: &str, cwd: &str) -> SharedProcess {
    let il = InterruptLocker::lock();

    let process: SharedProcess;

    {
        let mut binding = this();

        process = binding.create_process(name, cwd);
    }

    drop(il);

    process
}

pub fn create_thread(
    process: SharedProcess,
    entry: fn() -> (),
    stack_size: usize,
    priority: ThreadPriority,
    flags: ThreadFlags,
) {
    let il = InterruptLocker::lock();

    //

    {
        let mut binding = this();

        binding.create_thread(process, entry, stack_size, priority, flags);
    }

    //

    drop(il);
}

pub fn schedule() {
    let il = InterruptLocker::lock();

    //

    {
        // SAFETY: After `__context_switch` we can't get back to the scheduler handler.
        // After `ret` in `__context_switch` we will immediately jump to the entry point,
        // so `SCHEDULER` remains locked forever.
        // Our real guard are interrupt enabling and disabling, so we can safely unlock this mutex.
        unsafe { SCHEDULER.force_unlock() };

        let mut binding = this();

        if is_intiialized() {
            binding.schedule();
        }
    }

    //

    drop(il);
}

#[inline]
pub fn yield_now() {
    schedule();
}

pub fn this_thread() -> SharedThread {
    let thread: SharedThread;

    let il = InterruptLocker::lock();

    {
        // SAFETY: After `__context_switch` we can't get back to the scheduler handler.
        // After `ret` in `__context_switch` we will immediately jump to the entry point,
        // so `SCHEDULER` remains locked forever.
        // Our real guard are interrupt enabling and disabling, so we can safely unlock this mutex.
        unsafe { SCHEDULER.force_unlock() };

        let lock = this();

        thread = Arc::clone(lock.current_thread.as_ref().unwrap());
    }

    drop(il);

    thread
}

pub fn this_thread_id() -> usize {
    let id: usize;

    let il = InterruptLocker::lock();

    {
        let thread = this_thread();

        id = thread.id;
    }

    drop(il);

    id
}

pub fn in_kernel_context<T>(f: impl FnOnce() -> T) -> T {
    let il = InterruptLocker::lock();

    if !is_intiialized() {
        return f();
    }

    let this_cr3 = unsafe { x86::controlregs::cr3() };
    let kernel_cr3 = this().kernel_process().address_space.get().page_root_phys;

    unsafe { x86::controlregs::cr3_write(kernel_cr3 as _) };

    let result = f();

    unsafe { x86::controlregs::cr3_write(this_cr3 as _) };

    drop(il);

    result
}

pub fn sleep(dur: core::time::Duration) {
    let target = noct_time::systemclock::get_uptime_nanos() + dur.as_nanos();
    let ticks = noct_time::systemclock::nanos_to_ticks(target);

    let il = InterruptLocker::lock();

    {
        let mut sched = this();

        sched.sleep_this(ticks);
    }

    drop(il);

    // while crate::time::get_uptime_nanos() <= target {
    //     arch::halt();
    // }
}

// Exit from this thread.
pub fn thread_exit() -> ! {
    noct_interrupts::cpu::disable_interrupts();

    {
        let thread = this_thread();

        thread
            .state
            .store(thread::ThreadState::Dead as _, Ordering::SeqCst);

        {
            let mut lock = this();

            lock.sleeping_queue.retain(|(x, _)| x.id != thread.id);
            lock.working_queue.retain(|x| x.id != thread.id);

            lock.dead_queue.push_back(thread);
        }
    }

    schedule();

    unreachable!()
}

#[unsafe(naked)]
unsafe extern "C" fn thread_trampoline() -> ! {
    core::arch::naked_asm!(
        // Align ESP
        "sub esp, 4",
        // EBX = entry point
        "call ebx",
        // If entry returned, call thread_exit to mark thread as dead.
        "call {exit}",
        exit = sym thread_exit
    );
}

#[cfg(target_arch = "x86_64")]
#[unsafe(naked)]
unsafe extern "C" fn thread_trampoline64() -> ! {
    core::arch::naked_asm!(
        // Align RSP
        "sub rsp, 8",
        // RBX = entry point
        "call rbx",
        // If entry returned, call thread_exit to mark thread as dead.
        "call {exit}",
        exit = sym thread_exit
    );
}

#[unsafe(naked)]
unsafe extern "C" fn thread_trampoline_usermode() -> ! {
    core::arch::naked_asm!(
        "mov ax, 0x23",
        "mov ds, ax",
        "mov es, ax",
        "mov fs, ax",
        "mov gs, ax",
        "cli",
        "push 0x23",
        "push eax",
        "push 0x202",
        "push 0x1B",
        "push ebx",
        "iretd",
    );
}

fn idle_task() {
    loop {
        noct_cpu::halt::halt();
    }
}
