#![no_std]

extern crate alloc;

use core::time::Duration;

use alloc::vec::Vec;
use lazy_static::lazy_static;
use noct_descriptor::ResourceDescriptor;
pub use noct_input::*;

use noct_input::event::InputEvent;
use noct_sched::thread::{ThreadFlags, ThreadPriority};
use spin::Mutex;

/// A consumer that receives every input event outside of IRQ context.
///
/// The TTY uses this for stdin. Keeping sinks separate from the per-process
/// event queues lets the TTY own its queue without reaching into the kernel
/// process' descriptor table.
pub trait InputSink: Send + Sync {
    fn push_event(&self, event: InputEvent);
}

#[derive(Clone)]
pub struct EventListener {
    pub pid: usize,
    pub descriptor_fd: usize
}

lazy_static! {
    /// Event listeners registry is used to deliver events from kernel (actually drivers) to userspace.
    static ref EVENT_LISTENERS: Mutex<Vec<EventListener>> = Mutex::new(Vec::new());

    /// Input sinks are used by the kernel to delivers events INSIDE the kernel (from drivers to TTY).
    static ref SINKS: Mutex<Vec<&'static dyn InputSink>> = Mutex::new(Vec::new());
}

pub fn register(pid: usize, descriptor_fd: usize) {
    EVENT_LISTENERS.lock().push(EventListener { pid, descriptor_fd });
}

pub fn unregister(pid: usize, descriptor_fd: usize) {
    EVENT_LISTENERS
        .lock()
        .retain(|ev| !(ev.pid == pid && ev.descriptor_fd == descriptor_fd));
}

pub fn unregister_process(pid: usize) {
    EVENT_LISTENERS.lock().retain(|ev| ev.pid != pid);
}

pub fn register_sink(sink: &'static dyn InputSink) {
    SINKS.lock().push(sink);
}

pub fn register_this() -> usize {
    let event_queue = EventQueue::new();

    let (pid, descriptor_id) = {
        let process = &noct_sched::this_thread().process;

        let mut reslock = process.resources.lock();
        let descriptor = reslock.make(ResourceDescriptor::EventQueue(event_queue));

        (process.id, descriptor.id())
    };

    register(pid, descriptor_id);

    descriptor_id
}

/// Delivers one event to every registered consumer.
///
/// This must run in thread context (not IRQ).
/// It is called by the input dispatcher thread, never directly from an IRQ handler.
pub fn deliver_event(event: InputEvent) {
    // Snapshot the listener list so we never hold the listener lock while
    // taking a process resource lock.
    let listeners = EVENT_LISTENERS.lock().clone();

    let mut unavailable_processes = Vec::new();

    for &EventListener { pid, descriptor_fd: fd } in listeners.iter() {
        // Get the process. If it doesn't exist, push it to the unavailable process list.
        let Some(process) = noct_sched::get_process(pid) else {
            unavailable_processes.push(pid);
            continue;
        };

        let mut resources = process.resources.lock();

        // Find the input event queue descriptor.
        let Some(descriptor) = resources.find_mut(fd) else {
            continue;
        };

        // If there's some, push event there.
        if let Some(queue) = descriptor.res.as_event_queue_mut() {
            queue.push(event);
        }
    }

    if !unavailable_processes.is_empty() {
        let mut listeners = EVENT_LISTENERS.lock();

        for pid in unavailable_processes {
            listeners.retain(|ev| ev.pid != pid);
        }
    }

    // Free memory held by that Vec.
    drop(listeners);

    // Snapshot the sinks as well: a sink may take its own lock, and there is
    // no reason to keep the registry lock held while calling into it.
    let sinks = SINKS.lock().clone();

    for sink in sinks {
        sink.push_event(event);
    }
}

fn dispatcher_thread() {
    // A newly created thread may be entered while the scheduler still holds
    // its internal lock from the context switch.
    noct_sched::yield_now();

    noct_sched::sleep(Duration::from_millis(1));

    loop {
        while let Some(event) = pop_event() {
            deliver_event(event);
        }

        // A real wait queue can replace this polling loop later.
        noct_sched::sleep(Duration::from_millis(1));
    }
}

/// Starts the kernel input dispatcher thread.
///
/// It must be called after the TTY has registered its sink. (Long story short after TTY init)
pub fn init() {
    let process = noct_sched::this_process();

    noct_sched::create_thread(
        process,
        dispatcher_thread,
        32 << 10,
        ThreadPriority::Low,
        ThreadFlags::empty(),
        None,
        &[],
    )
    .expect("Failed to create input dispatcher thread");
}
