#![no_std]

extern crate alloc;

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

pub fn deliver_event(ev: InputEvent) {
    qemu_log!("Listeners: {}", EVENT_LISTENERS.lock().len());

    for &(pid, fd) in EVENT_LISTENERS.lock().iter() {
        qemu_log!("- Listener: {:?}", (pid, fd));

        let Some(proc) = noct_sched::get_process(pid) else {
            qemu_log!("Failed to get a process");

            continue;
        };

        qemu_log!("Got a process");

        let mut bind = proc.resources.lock();

        let Some(res) = bind.find_mut(fd) else {
            qemu_log!("Failed to get a fd");

            continue;
        };

        res.res.as_event_queue_mut().unwrap().push(ev.clone());
    }

    noct_sched::resume_group(ThreadWaitReason::InputEvent);
}