#![no_std]

extern crate alloc;

use noct_descriptor::ResourceDescriptor;
pub use noct_input::*;

use alloc::vec::Vec;
use noct_input::event::InputEvent;

use lazy_static::lazy_static;
use noct_logger::qemu_log;
use noct_sched::thread::ThreadWaitReason;
use spin::Mutex;

lazy_static! {
    static ref EVENT_LISTENERS: Mutex<Vec<(usize, usize)>> = Mutex::new(Vec::new());
}

pub fn register(pid: usize, descriptor_id: usize) {
    EVENT_LISTENERS.lock().push((pid, descriptor_id));
}

pub fn unregister(pid: usize, descriptor_id: usize) {
    EVENT_LISTENERS.lock().retain(|&(p, d)| !(p == pid && d == descriptor_id));
}

pub fn register_this() -> usize {
    let event_queue = noct_input::EventQueue::new();

    let process = &noct_sched::this_thread().process;

    let mut reslock = process.resources.lock();

    let descr = reslock.make(ResourceDescriptor::EventQueue(event_queue));

    register(process.id, descr.id());

    descr.id()
}

pub fn deliver_event(ev: InputEvent) {
    qemu_log!("Listeners: {}", EVENT_LISTENERS.lock().len());

    let mut unavailable_processes: Vec<usize> = Vec::new();

    // Traverse through all listeners.
    for &(pid, fd) in EVENT_LISTENERS.lock().iter() {
        qemu_log!("- Listener: {:?}", (pid, fd));

        // Get process control block.
        let Some(proc) = noct_sched::get_process(pid) else {
            qemu_log!("Failed to get a process, scheduled to remove from listeners");

            // If failed to get a process, push it to the unavailable process list.
            unavailable_processes.push(pid);

            continue;
        };

        qemu_log!("Got a process");

        let mut bind = proc.resources.lock();

        // Find registered FD.
        let Some(res) = bind.find_mut(fd) else {
            qemu_log!("Failed to get a fd");

            continue;
        };

        // Push last event to the descriptor.
        res.res.as_event_queue_mut().unwrap().push(ev.clone());
    }

    // Remove all processes that failed.
    for pid in unavailable_processes {
        qemu_log!("Removing unavailable process from listeners: {}", pid);

        EVENT_LISTENERS.lock().retain(|&(p, _)| p != pid);
    }

    // Signal everyone that input is delivered.
    noct_sched::resume_group(ThreadWaitReason::InputEvent);
}