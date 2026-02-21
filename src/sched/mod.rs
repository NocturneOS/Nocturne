
use core::{
    alloc::Layout,
    cell::{Cell},
    sync::atomic::{AtomicUsize, Ordering},
};

use alloc::{
    collections::{linked_list::LinkedList, vec_deque::VecDeque},
    sync::Arc,
};
use lazy_static::lazy_static;
use spin::{Mutex, MutexGuard};

use crate::{
    arch, qemu_log,
    sched::{
        archspec::ArchitectureSpecificRegion,
        process::Process,
        thread::{Thread, ThreadFlags, ThreadPriority, ThreadState},
    }, tools::interrupt_locker::InterruptLocker,
};

mod archspec;
pub mod process;
pub mod thread;

pub const KERNEL_THREAD_DEFAULT_STACK_SIZE: usize = 64 << 10;  // 64 KB

lazy_static! {
    static ref SCHEDULER: Mutex<Scheduler> = Mutex::new(Scheduler::new());
    static ref GLOBAL_TID: AtomicUsize = AtomicUsize::new(0);
}

pub type SharedProcess = Arc<Process>;
pub type SharedThread = Arc<Thread>;

pub struct Scheduler {
    pub is_initialized: bool,

    process_list: LinkedList<SharedProcess>,
    thread_list: LinkedList<SharedThread>,

    working_queue: LinkedList<SharedThread>,
    sleeping_queue: VecDeque<(SharedThread, u128)>,
    dead_queue: LinkedList<SharedThread>,

    idle_task: Option<SharedThread>,

    current_process: Option<SharedProcess>,
    current_thread: Option<SharedThread>,
}

unsafe extern "C" {
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
            is_initialized: false,

            process_list: LinkedList::new(),
            thread_list: LinkedList::new(),

            working_queue: LinkedList::new(),
            sleeping_queue: VecDeque::new(),
            dead_queue: LinkedList::new(),

            idle_task: None,

            current_process: None,
            current_thread: None,
        }
    }

    pub fn init(&mut self) {
        let kernel_process = Process::new(
            unsafe { x86::controlregs::cr3() as _ },
            unsafe { x86::controlregs::cr3() as _ },
            "kernel",
            "",
        );

        let kernel_process = Arc::new(kernel_process);

        let kernel_thread = Thread {
            id: next_tid(),

            process: Arc::clone(&kernel_process), //Arc::into_raw(Arc::clone(&kernel_process)).into(),
            flags: ThreadFlags::empty(),
            state: (thread::ThreadState::Running as usize).into(),
            stack_size: 64 << 10, // 64 KB
            arch_specific_region: ArchitectureSpecificRegion::new(),
            
            priority: thread::ThreadPriority::Low,
            time_quantum: 1.into(),
            last_error: 0.into(),

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
            ThreadPriority::Low,
            ThreadFlags::Raw,
        );

        self.process_list.push_back(kernel_process);
        self.thread_list.push_back(Arc::clone(&kernel_thread));

        self.working_queue.push_back(kernel_thread);

        self.is_initialized = true;
    }

    pub fn create_thread(
        &mut self,
        process: SharedProcess,
        entry: fn() -> (),
        stack_size: usize,
        priority: ThreadPriority,
        flags: ThreadFlags,
    ) -> Option<SharedThread> {
        let stack: *mut u8 = unsafe {
            alloc::alloc::alloc_zeroed(Layout::from_size_align(stack_size, 0x1000).ok()?)
        };

        let id = next_tid();

        let mut writeable_sp = (stack.addr() + stack_size) as *mut usize;

        #[cfg(target_arch = "x86")]
        unsafe {
            writeable_sp = writeable_sp.sub(1);
            writeable_sp.write(thread_exit as *const () as usize);

            writeable_sp = writeable_sp.sub(1);
            writeable_sp.write(entry as *const () as usize);

            writeable_sp = writeable_sp.sub(1);
            writeable_sp.write(0x202); // IF=1, IOPL=0

            writeable_sp = writeable_sp.sub(1);
            writeable_sp.write(0); // EAX
            writeable_sp = writeable_sp.sub(1);
            writeable_sp.write(0); // EBX
            writeable_sp = writeable_sp.sub(1);
            writeable_sp.write(0); // ECX
            writeable_sp = writeable_sp.sub(1);
            writeable_sp.write(0); // EDX
            writeable_sp = writeable_sp.sub(1);
            writeable_sp.write(0); // ESI
            writeable_sp = writeable_sp.sub(1);
            writeable_sp.write(0); // EDI
            writeable_sp = writeable_sp.sub(1);
            writeable_sp.write(0); // EBP
        }

        #[cfg(target_arch = "x86_64")]
        unsafe {
            writeable_sp = writeable_sp.sub(1);
            writeable_sp.write(0);

            writeable_sp = writeable_sp.sub(1);
            writeable_sp.write(thread_trampoline as *const () as usize);

            writeable_sp = writeable_sp.sub(1);
            writeable_sp.write(0x202); // IF=1, IOPL=0

            writeable_sp = writeable_sp.sub(1);
            writeable_sp.write(0); // RAX
            writeable_sp = writeable_sp.sub(1);
            writeable_sp.write(entry as *const() as usize); // RBX = entry
            writeable_sp = writeable_sp.sub(1);
            writeable_sp.write(0); // RCX
            writeable_sp = writeable_sp.sub(1);
            writeable_sp.write(0); // RDX
            writeable_sp = writeable_sp.sub(1);
            writeable_sp.write(0); // RSI
            writeable_sp = writeable_sp.sub(1);
            writeable_sp.write(0); // RDI
            writeable_sp = writeable_sp.sub(1);
            writeable_sp.write(0); // RBP
            writeable_sp = writeable_sp.sub(1);
            writeable_sp.write(0); // R8
            writeable_sp = writeable_sp.sub(1);
            writeable_sp.write(0); // R9
            writeable_sp = writeable_sp.sub(1);
            writeable_sp.write(0); // R10
            writeable_sp = writeable_sp.sub(1);
            writeable_sp.write(0); // R11
            writeable_sp = writeable_sp.sub(1);
            writeable_sp.write(0); // R12
            writeable_sp = writeable_sp.sub(1);
            writeable_sp.write(0); // R13
            writeable_sp = writeable_sp.sub(1);
            writeable_sp.write(0); // R14
            writeable_sp = writeable_sp.sub(1);
            writeable_sp.write(0); // R15
        }

        // qemu_log!("STACK: {:08x?}; ESP: {:08x?}", stack.addr(), writeable_sp.addr());

        process.thread_count.fetch_add(1, Ordering::SeqCst);

        let tcb = Thread {
            id,
            process, //Arc::into_raw(process),
            flags,
            state: (thread::ThreadState::Ready as usize).into(),
            stack_addr: stack.addr(),
            stack_size,
            stack_pointer: writeable_sp.addr(),
            entry_point: entry as *const () as usize,
            arch_specific_region: ArchitectureSpecificRegion::new(),
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

        let layout = Layout::from_size_align(thread.stack_size, 0x1000).unwrap();
        let stack = thread.stack_addr as *mut u8;

        unsafe { alloc::alloc::dealloc(stack, layout) };

        (*thread.process)
            .thread_count
            .fetch_sub(1, Ordering::SeqCst);
    }

    #[inline(always)]
    fn this_task(&self) -> &SharedThread {
        self.current_thread.as_ref().unwrap()
    }

    fn sleep_this(&mut self, wakeup_time_ticks: u128) {
        self.current_thread
            .as_ref()
            .unwrap()
            .state
            .store(ThreadState::Sleeping as usize, Ordering::SeqCst);

        self.working_queue.retain(|x| x.id != self.current_thread.as_ref().unwrap().id);

        self.sleeping_queue.push_back((
            Arc::clone(self.this_task()),
            wakeup_time_ticks,
        ));

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

            if crate::time::get_uptime_ticks() > *wakeup_time {
                task.state.store(ThreadState::Ready as usize, Ordering::SeqCst);

                self.working_queue.push_back(Arc::clone(task));

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
            let thread_state: thread::ThreadState = thread::ThreadState::from(t.state.load(Ordering::SeqCst));

            debug_assert!(thread_state != ThreadState::Dead, "Found a dead task in the working queue!");
            debug_assert!(thread_state != ThreadState::Sleeping, "Found a sleeping task in the working queue!");

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

        // If it's not an idle task, check it.
        if !Arc::ptr_eq(&this, self.idle_task.as_ref().unwrap()) {
            let state = thread::ThreadState::from(this.state.load(Ordering::SeqCst));

            // If it's running or ready, push it to the queue.
            if state == ThreadState::Ready || state == ThreadState::Running {
                // If we DIDN'T ran out of quantum, decrement and continue.
                if this.time_quantum.load(Ordering::SeqCst) != 0 {
                    this.time_quantum.fetch_sub(1, Ordering::SeqCst);
                    return;
                }
                
                // Reload ammo.
                this.time_quantum.store(this.priority.to_ticks().into(), Ordering::SeqCst);

                this.state.store(ThreadState::Ready as _, Ordering::SeqCst);

                self.working_queue.push_back(Arc::clone(&this));
            }
        }

        let next = self.next_task();

        this.state.store(ThreadState::Running as _, Ordering::SeqCst);

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

pub fn create_thread(entry: fn() -> (), stack_size: usize, priority: ThreadPriority, flags: ThreadFlags) {
    let il = InterruptLocker::lock();

    //

    {
        let proc = this_process_unlocked();
        let mut binding = this();

        binding.create_thread(proc, entry, stack_size, priority, flags);
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

        if binding.is_initialized {
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

pub fn sleep(dur: core::time::Duration) {
    let target = crate::time::get_uptime_nanos() + dur.as_nanos();
    let ticks = crate::time::nanos_to_ticks(target);

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
    arch::disable_interrupts();

    {
        let thread = this_thread();

        thread.state.store(thread::ThreadState::Dead as _, Ordering::SeqCst);

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
        // Align RSP
        "sub rsp, 8",
        // RBX = entry point
        "call rbx",
        // If entry returned, call thread_exit to mark thread as dead.
        "call {exit}",
        exit = sym thread_exit
    );
}

fn idle_task() {
    loop {
        arch::halt();
    }
}
