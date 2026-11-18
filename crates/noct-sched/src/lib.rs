#![no_std]
#![feature(linked_list_retain)]

extern crate alloc;

use core::{
    ffi::CStr,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
    time::Duration,
};

use alloc::{
    collections::{linked_list::LinkedList, vec_deque::VecDeque, BTreeMap},
    sync::Arc,
    vec::Vec,
};
use lazy_static::lazy_static;
use noct_spec::KERNEL_BASE;
use noct_tools::interrupt_locker::InterruptLocker;
use spin::{Mutex, MutexGuard};

use noct_logger::qemu_log;

use crate::process::{PROCESS_NO_PARENT, ProcessEntry, ProcessHandle, ProcessState};

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

pub const KERNEL_THREAD_DEFAULT_STACK_SIZE: usize = 256 << 10; // 256 KB

lazy_static! {
    static ref IS_SCHEDULER_INITIALIZED: AtomicBool = AtomicBool::default();
    static ref SCHEDULER: Mutex<Scheduler> = Mutex::new(Scheduler::new());
    static ref GLOBAL_TID: AtomicUsize = AtomicUsize::new(0);
}

pub type SharedProcess = Arc<Process>;
pub type SharedThread = Arc<Thread>;

pub struct Scheduler {
    thread_list: LinkedList<SharedThread>,

    working_queue: LinkedList<SharedThread>,
    sleeping_queue: VecDeque<(SharedThread, u128)>,
    waiting_queue: VecDeque<SharedThread>,
    dead_queue: LinkedList<SharedThread>,

    idle_task: Option<SharedThread>,

    current_process: Option<SharedProcess>,
    current_thread: Option<SharedThread>,

    kernel_process: Option<SharedProcess>,

    process_table: BTreeMap<usize, process::ProcessEntry>,
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
    GLOBAL_TID.fetch_add(1, Ordering::Acquire)
}

impl Scheduler {
    pub const fn new() -> Self {
        Self {
            thread_list: LinkedList::new(),

            working_queue: LinkedList::new(),
            sleeping_queue: VecDeque::new(),
            waiting_queue: VecDeque::new(),
            dead_queue: LinkedList::new(),

            idle_task: None,

            current_process: None,
            current_thread: None,

            kernel_process: None,

            process_table: BTreeMap::new()
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

            process: Arc::clone(&kernel_process),
            flags: ThreadFlags::empty(),
            state: (thread::ThreadState::Running as usize).into(),
            // SAFETY: Kernel thread's stack will be overwritten on first context switch (on context save phase).
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
            wait_reason: (thread::ThreadWaitReason::None).into(),
        };

        let kernel_thread = Arc::new(kernel_thread);

        self.current_process = Some(Arc::clone(&kernel_process));
        self.current_thread = Some(Arc::clone(&kernel_thread));

        self.idle_task = self
            .create_thread(
                Arc::clone(&kernel_process),
                idle_task,
                16 << 10,    // 16 KB should be enough.
                ThreadPriority::Low,
                ThreadFlags::Raw,
                &[],
            )
            .or_else(|| panic!("Failed to create idle task thread"));

        self.thread_list.push_back(Arc::clone(&kernel_thread));

        self.working_queue.push_back(kernel_thread);

        IS_SCHEDULER_INITIALIZED.store(true, Ordering::Release);
    }

    pub fn kernel_process(&self) -> &SharedProcess {
        self.kernel_process.as_ref().unwrap()
    }

    pub fn create_process(&mut self, name: &str, cwd: &str) -> SharedProcess {
        let this_proc = &self.this_task().process;
        let proc = Process::new(name, cwd);

        self.process_table.insert(
            proc.id,
            ProcessEntry::alive(this_proc.id, proc.into_handle_ref()),
        );

        Arc::new(proc)
    }

    pub fn create_thread(
        &mut self,
        process: SharedProcess,
        entry: fn() -> (),
        stack_size: usize,
        priority: ThreadPriority,
        flags: ThreadFlags,
        args: &[usize],
    ) -> Option<SharedThread> {
        let is_user_proc = process.id != 0;

        let mut addrspace = unsafe { process.address_space.pseudo_lock() };

        let mut stack = if is_user_proc {
            ThreadStack::new_user(&mut addrspace, stack_size)
        } else {
            ThreadStack::new(stack_size)
        };

        qemu_log!(
            "Stack allocated: base @ {:#x?} [{:#x?} - {:#x?}]",
            stack.stack_addr,
            stack.stack_addr,
            stack.stack_addr + stack.stack_size
        );

        let id = next_tid();
        let archspec = ArchitectureSpecificRegion::new();

        //let kst = archspec.tss_kernel_stack.load(Ordering::Relaxed);

        // Push args onto the stack.
        for i in args {
            unsafe { stack.push(&mut addrspace, *i) };
        }

        let stack_top = stack.stack_pointer;

        qemu_log!("               : pointer @ {:#x?}", stack_top);

        #[cfg(target_arch = "x86")]
        unsafe {
            if is_user_proc {
                stack.push(
                    addrspace,
                    thread_trampoline_usermode as *const () as usize,
                );
            } else {
                // stack.push(
                //     addrspace,
                //     thread_exit as *const () as usize,
                // );

                stack.push(
                    addrspace,
                    thread_trampoline as *const () as usize,
                );
            }

            stack.push(addrspace, 0x202); // IF=1, IOPL=0

            stack.push(addrspace, stack_top as usize); // EAX
            stack.push(addrspace, entry as *const () as usize); // EBX
            stack.push(addrspace, 0); // ECX
            stack.push(addrspace, 0); // EDX
            stack.push(addrspace, 0); // ESI
            stack.push(addrspace, 0); // EDI
            stack.push(addrspace, 0); // EBP
        }

        #[cfg(target_arch = "x86_64")]
        unsafe {
            stack.push(addrspace, 0);

            if is_user_proc {
                // todo!("Usermode trampoline for x86_64")
                stack.push(
                    addrspace,
                    thread_trampoline_usermode64 as *const () as usize,
                );
            } else {
                stack.push(
                    addrspace,
                    thread_trampoline64 as *const () as usize,
                );
            }

            stack.push(addrspace, 0x202); // IF=1, IOPL=0

            stack.push(addrspace, stack_top as usize); // RAX
            stack.push(addrspace, entry as *const () as usize); // RBX = entry
            stack.push(addrspace, 0); // RCX
            stack.push(addrspace, 0); // RDX
            stack.push(addrspace, 0); // RSI
            stack.push(addrspace, 0); // RDI
            stack.push(addrspace, 0); // RBP
            stack.push(addrspace, 0); // R8
            stack.push(addrspace, 0); // R9
            stack.push(addrspace, 0); // R10
            stack.push(addrspace, 0); // R11
            stack.push(addrspace, 0); // R12
            stack.push(addrspace, 0); // R13
            stack.push(addrspace, 0); // R14
            stack.push(addrspace, 0); // R15
        }

        // Drop the lock
        drop(addrspace);

        // qemu_log!("STACK: {:08x?}", unsafe { stack.pointer().addr() });

        process.thread_count.fetch_add(1, Ordering::Release);

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
            wait_reason: (thread::ThreadWaitReason::None).into(),
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
            let mut address_space = unsafe { thread.process.address_space.pseudo_lock() };
            let stack_addr = thread.stack.stack_addr;

            // Count guard page in.
            let addr = stack_addr - noct_mem::paging::PAGE_SIZE;

            address_space
                .unmap_pages(stack_addr, thread.stack.stack_size);

            address_space.free_virt_region(addr);

            // Physical stack frames are owned by `ThreadStack::pa`; they are
            // released when the thread is dropped below.
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

        //qemu_log!("Strong count: {:?}", Arc::strong_count(&thread));

        (*thread.process)
            .thread_count
            .fetch_sub(1, Ordering::Release);

        drop(thread);
    }

    #[inline(always)]
    fn this_task(&self) -> &SharedThread {
        self.current_thread.as_ref().unwrap()
    }

    /// Puts current thread into sleep state.
    fn sleep_this(&mut self, wakeup_time_ticks: u128) {
        // Set Sleeping state
        self.current_thread
            .as_ref()
            .unwrap()
            .state
            .store(ThreadState::Sleeping as usize, Ordering::Release);

        // Remove this thread from working queue.
        self.working_queue
            .retain(|x| x.id != self.current_thread.as_ref().unwrap().id);

        // Push it to sleeping queue.
        self.sleeping_queue
            .push_back((Arc::clone(self.this_task()), wakeup_time_ticks));

        self.schedule();
    }

    // Puts current thread into waiting state with specific reason.
    fn pause(&mut self, reason: thread::ThreadWaitReason) {
        // Set Waiting state
        let thread = self.this_task();

        thread
            .state
            .store(ThreadState::Waiting as usize, Ordering::Release);

        *thread.wait_reason.lock() = reason;

        let thread = Arc::clone(thread);

        // Remove this thread from working queue.
        self.working_queue.retain(|x| x.id != thread.id);

        // Push it to waiting queue.
        self.waiting_queue.push_back(thread);

        self.schedule();
    }

    /// Resumes a specific thread from waiting state.
    /// If reschedule is true, it will immediately schedule the next thread.
    fn resume(&mut self, thread: SharedThread, reschedule: bool) {
        // Set Ready state
        thread
            .state
            .store(ThreadState::Ready as usize, Ordering::Release);

        // Remove this thread from waiting queue.
        self.waiting_queue.retain(|x| x.id != thread.id);

        // Push it to working queue.
        self.working_queue.push_back(thread);

        if reschedule {
            self.schedule();
        }
    }

    // Resumes all threads from waiting state with specific reason.
    fn resume_group(&mut self, reason: thread::ThreadWaitReason) {
        if reason == thread::ThreadWaitReason::None {
            return;
        }

        if reason == thread::ThreadWaitReason::User {
            qemu_log!("Cannot bulk-resume threads paused by the user. Use `resume` instead.");

            return;
        }

        // Collect threads into a dedicated Vec to avoid double borrow of self.waiting_queue.
        let mut to_resume = Vec::new();

        for thread in self.waiting_queue.iter() {
            let wait_reason = *thread.wait_reason.lock();

            if wait_reason == reason {
                to_resume.push(Arc::clone(thread));
            }
        }

        for thread in to_resume {
            self.resume(thread, false);
        }

        self.schedule();
    }

    #[inline(always)]
    fn check_dead_tasks(&mut self) {
        // `remove_task` frees the thread's stack, so the thread that is currently
        // executing must not be reaped here. It stays in the queue and will be
        // reaped by whichever thread schedules next.
        let current_id = self.current_thread.as_ref().map(|t| t.id);

        let mut not_reapable = LinkedList::new();

        while let Some(task) = self.dead_queue.pop_front() {
            if Some(task.id) == current_id {
                not_reapable.push_back(task);
            } else {
                self.remove_task(task);
            }
        }

        self.dead_queue = not_reapable;
    }

    /// Marks a process as finished and makes its exit status available to `waitpid`.
    ///
    /// Must be called with the scheduler lock held.
    fn mark_process_exited(&mut self, proc_id: usize, exit_code: u32) {
        let is_orphan = match self.process_table.get(&proc_id) {
            Some(entry) => {
                entry.handle().exit_code.store(exit_code, Ordering::Release);

                entry.parent_pid() == PROCESS_NO_PARENT
            }
            // The process was already reaped (e.g. it was discarded while its
            // owning pid was being cleaned up), there is nobody to report the
            // status to.
            None => return,
        };

        if is_orphan {
            // Nobody can wait for an orphan, so drop the entry right away
            // instead of leaking a zombie.
            self.process_table.remove(&proc_id);

            return;
        }

        self.process_table
            .get_mut(&proc_id)
            .unwrap()
            .set_state(ProcessState::Zombie);
    }

    /// Called when a process dies: gives its children to the kernel process and
    /// drops zombie children, since nobody can wait for them anymore.
    fn orphan_children_of(&mut self, proc_id: usize) {
        self.process_table.retain(|_, entry| {
            if entry.parent_pid() != proc_id {
                return true;
            }

            if entry.state() == ProcessState::Zombie {
                return false;
            }

            entry.set_parent_pid(PROCESS_NO_PARENT);

            true
        });
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
                    .store(ThreadState::Ready as usize, Ordering::Release);

                self.working_queue.push_front(Arc::clone(task));

                self.sleeping_queue.remove(index);

                len -= 1;

                continue;
            }

            index += 1;
        }
    }

    fn next_task(&mut self) -> SharedThread {
        // Dead threads may belong to processes whose page tables are not the
        // currently loaded ones, so it is safe to reap them here as long as we
        // skip the thread that is still executing (see [`Scheduler::check_dead_tasks`]).
        self.check_dead_tasks();

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
                    this.time_quantum.fetch_sub(1, Ordering::Relaxed);
                    return;
                }

                // Reload ammo.
                this.time_quantum
                    .store(this.priority.to_ticks().into(), Ordering::Release);

                this.state.store(ThreadState::Ready as _, Ordering::Release);

                self.working_queue.push_back(Arc::clone(&this));
            }
        }

        let next = self.next_task();

        this.state
            .store(ThreadState::Running as _, Ordering::Release);

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
    IS_SCHEDULER_INITIALIZED.load(Ordering::Acquire)
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
    unsafe { SCHEDULER.force_unlock() };

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

pub fn create_process_inherit(name: &str) -> SharedProcess {
    let cwd = unsafe { CStr::from_ptr(this_process().cwd.load(Ordering::Acquire)) }
        .to_str()
        .unwrap();

    let il = InterruptLocker::lock();

    let process: SharedProcess;

    {
        let mut binding = this();

        process = binding.create_process(name, cwd);
    }

    drop(il);

    process
}

/// Creates a thread and returns its global TID.
pub fn create_thread(
    process: SharedProcess,
    entry: fn() -> (),
    stack_size: usize,
    priority: ThreadPriority,
    flags: ThreadFlags,
    args: &[usize],
) -> Option<usize> {
    let il = InterruptLocker::lock();

    let id: usize;

    //

    {
        let mut binding = this();

        let thread = binding.create_thread(process, entry, stack_size, priority, flags, args)?;

        id = thread.id;
    }

    //

    drop(il);

    Some(id)
}

pub fn schedule() {
    let il = InterruptLocker::lock();

    //

    {
        // SAFETY: After `__context_switch` we can't get back to the scheduler handler.
        //         After `ret` in `__context_switch` we will immediately jump to the entry point,
        //         so `SCHEDULER` remains locked forever.
        //         Our real guard are interrupt enabling and disabling, so we can safely unlock this mutex.
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
        //         After `ret` in `__context_switch` we will immediately jump to the entry point,
        //         so `SCHEDULER` remains locked forever.
        //         Our real guard are interrupt enabling and disabling, so we can safely unlock this mutex.
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
    let target = noct_time::systemclock::get_uptime_nanos() + dur.as_nanos();
    let ticks = noct_time::systemclock::nanos_to_ticks(target);

    let il = InterruptLocker::lock();

    {
        let mut sched = this();

        sched.sleep_this(ticks);
    }

    drop(il);
}

pub fn pause(reason: thread::ThreadWaitReason) {
    let il = InterruptLocker::lock();

    {
        let mut sched = this();

        sched.pause(reason);
    }

    drop(il);
}

pub fn resume(thread: SharedThread, reschedule: bool) {
    let il = InterruptLocker::lock();

    {
        let mut sched = this();

        sched.resume(thread, reschedule);
    }

    drop(il);
}

pub fn resume_group(reason: thread::ThreadWaitReason) {
    let il = InterruptLocker::lock();

    {
        let mut sched = this();

        sched.resume_group(reason);
    }

    drop(il);
}

pub fn get_process(pid: usize) -> Option<Arc<Process>> {
    let il = InterruptLocker::lock();

    // The scheduler lock is intentionally left held across a context switch
    // and force-unlocked by the next scheduler entry. Accessors that may run
    // on a freshly scheduled thread (such as the input dispatcher) must do
    // the same before taking the lock.
    unsafe { SCHEDULER.force_unlock() };

    let result = this()
        .thread_list
        .iter()
        .find(|x| x.process.id == pid)
        .map(|x| Arc::clone(&x.process));

    drop(il);

    result
}

pub fn get_process_handle(pid: usize) -> Option<Arc<ProcessHandle>> {
    let il = InterruptLocker::lock();

    let result = this()
        .process_table
        .get(&pid)
        .map(|x| Arc::clone(&x.handle()));

    drop(il);

    result
}

/// Removes a process from the process table without waiting for it.
///
/// Used when a process could not be fully created (e.g. thread creation failed).
pub fn discard_process_entry(pid: usize) {
    noct_tools::without_interrupts::without_interrupts(|| {
        this().process_table.remove(&pid);
    });
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum WaitError {
    /// There is no process with this PID, or it is not a child of the caller.
    NoChild,
    /// A process tried to wait for itself.
    SelfWait,
}

/// Waits for a child process to complete and returns its exit code.
///
/// The exit status is kept in the process table after the process itself has
/// been destroyed, so it does not matter whether the child finished before or
/// after this call was made.
pub fn waitpid(pid: usize) -> Result<u32, WaitError> {
    loop {
        {
            let _il = InterruptLocker::lock();

            let mut sched = this();

            let current_pid = sched
                .current_process
                .as_ref()
                .map(|p| p.id)
                .ok_or(WaitError::NoChild)?;

            // Waiting for yourself would block forever.
            if pid == current_pid {
                return Err(WaitError::SelfWait);
            }

            let entry = sched
                .process_table
                .get_mut(&pid)
                .ok_or(WaitError::NoChild)?;

            // Only the parent is allowed to consume the child's exit status.
            if entry.parent_pid() != current_pid {
                return Err(WaitError::NoChild);
            }

            if entry.state() == ProcessState::Zombie {
                let code = entry.handle().exit_code.load(Ordering::Acquire);

                // Consuming the status reaps the zombie.
                sched.process_table.remove(&pid);

                return Ok(code);
            }
        }

        // TODO: Replace polling with a `ThreadWaitReason::WaitingForChild` and
        //       resume this thread from `process_exit`/`thread_exit` instead.
        sleep(Duration::from_millis(1));
    }
}

#[deprecated]
pub fn set_error(value: usize) {
    this_thread().last_error.store(value, Ordering::Release)
}

// Exit from this thread.
pub fn thread_exit() -> ! {
    noct_interrupts::cpu::disable_interrupts();

    {
        let thread = this_thread();

        thread
            .state
            .store(thread::ThreadState::Dead as _, Ordering::Release);

        {
            let mut lock = this();

            // `thread_count` counts threads that have not been reaped yet, so it
            // cannot be used to detect the last *live* thread. Count those instead.
            let live_threads = lock
                .thread_list
                .iter()
                .filter(|x| x.process.id == thread.process.id)
                .filter(|x| {
                    thread::ThreadState::from(x.state.load(Ordering::Relaxed))
                        != thread::ThreadState::Dead
                })
                .count();

            if live_threads == 0 {
                // This was the last thread of the process, so report the process'
                // termination to the process table (the kernel process has no handle).
                if let Some(handle) = thread.process.handle.as_ref() {
                    handle.exit_code.store(0, Ordering::Release);
                }

                lock.mark_process_exited(thread.process.id, 0);
            }

            lock.sleeping_queue.retain(|(x, _)| x.id != thread.id);
            lock.working_queue.retain(|x| x.id != thread.id);
            lock.waiting_queue.retain(|x| x.id != thread.id);

            lock.dead_queue.push_back(thread);
        }
    }

    schedule();

    unreachable!()
}

pub fn process_exit(exitcode: u32) -> ! {
    noct_interrupts::cpu::disable_interrupts();

    {
        let thread = this_thread();
        let proc_id = thread.process.id;

        if let Some(handle) = thread.process.handle.as_ref() {
            handle.exit_code.store(exitcode, Ordering::Release);
        }

        {
            let mut lock = this();

            lock.mark_process_exited(proc_id, exitcode);
            lock.orphan_children_of(proc_id);

            // Skip threads that already exited (they are in the dead queue and
            // pushing them again would cause a double reap) and the current one,
            // which is still Running.
            let list: Vec<Arc<Thread>> = lock
                .thread_list
                .iter()
                .filter(|x| x.process.id == proc_id)
                .filter(|x| {
                    thread::ThreadState::from(x.state.load(Ordering::Relaxed))
                        != thread::ThreadState::Dead
                })
                .cloned()
                .collect();

            for i in list {
                i.state
                    .store(thread::ThreadState::Dead as _, Ordering::Release);

                lock.sleeping_queue.retain(|(x, _)| x.id != i.id);
                lock.working_queue.retain(|x| x.id != i.id);
                lock.waiting_queue.retain(|x| x.id != i.id);

                lock.dead_queue.push_back(i);
            }
        }
    }

    schedule();

    unreachable!()
}

#[cfg(target_arch = "x86")]
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
    )
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
    )
}

#[cfg(target_arch = "x86")]
#[unsafe(naked)]
unsafe extern "C" fn thread_trampoline_usermode() -> ! {
    core::arch::naked_asm!(
        "push eax",     // EAX is thread's ESP. Save it to avoid data corruption.
        "mov ax, 0x23", // 0x23 - is GDT selector 0x20 orred by 3 (ring 3).
        "mov ds, ax",
        "mov es, ax",
        "mov fs, ax",
        "mov gs, ax",
        "pop eax", // Restore EAX.
        "cli",
        "push 0x23",  // Stack selector = Data selector = 0x20 | 3
        "push eax",   // SS:ESP = 0x23:EAX
        "push 0x202", // EFLAGS with IF (interrupt flag enabled)
        "push 0x1B",  // Code selector | 3
        "push ebx",   // Entry point = EIP
        // "hlt",
        "iretd",
    );
}

#[cfg(target_arch = "x86_64")]
#[unsafe(naked)]
unsafe extern "C" fn thread_trampoline_usermode64() -> ! {
    core::arch::naked_asm!(
        "push rax",     // RAX is thread's RSP. Save it to avoid data corruption.
        "mov ax, 0x23", // 0x23 - is GDT selector 0x20 orred by 3 (ring 3).
        "mov ds, ax",
        "mov es, ax",
        "mov fs, ax",
        "mov gs, ax",
        "pop rax", // Restore RAX.
        "cli",
        "push 0x1B",  // Stack selector = Data selector = 0x18 | 3
        "push rax",   // SS:RSP = 0x18:RAX
        "push 0x202", // RFLAGS with IF (interrupt flag enabled)
        "push 0x23",  // Code selector | 3
        "push rbx",   // Entry point = RIP
        // "hlt",
        "iretq",
    )
}

fn idle_task() {
    loop {
        noct_cpu::halt::halt();
    }
}
