#![no_std]
#![allow(static_mut_refs)]

extern crate alloc;

use alloc::{collections::vec_deque::VecDeque};
use noct_tools::{without_interrupts::without_interrupts};
use spin::{Once, RwLock};

use crate::event::InputEvent;

pub mod event;
pub mod keyboard;
pub mod mouse;

/// Global keyboard buffer (kernel-wide). Used everywhere.
static EVENT_QUEUE: RwLock<spin::Once<EventQueue>> = RwLock::new(Once::new());

/// A definition of Keyboard buffer. It's just a pre-allocated vector, but functionality can be extended soon and new fields may be added.
pub struct EventQueue {
    buffer: VecDeque<InputEvent>,
}

impl EventQueue {
    const QUEUE_SIZE: usize = 1024;

    /// Creates a new event queue instance.
    pub fn new() -> Self {
        let buffer = VecDeque::with_capacity(Self::QUEUE_SIZE);

        Self { buffer }
    }

    /// Push a event into a buffer.
    pub fn push(&mut self, event: InputEvent) {
        let bind = &mut self.buffer;

        // Bound the buffer, so it won't grow endlessly.
        if bind.len() >= Self::QUEUE_SIZE {
            bind.pop_front();
        }

        bind.push_back(event);
    }

    /// Pop a event from a buffer, just calls for Vec::pop().
    pub fn get_raw(&mut self) -> Option<InputEvent> {
        let bind = &mut self.buffer;
        
        bind.pop_front()
    }

    /// Polls for a event from a buffer.
    pub fn get(&mut self) -> InputEvent {
        while self.buffer.is_empty() {
            // TODO: Uncomment that when SMP is implemented.
            // core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::Acquire);

            noct_sched::yield_now();
        }

        self.get_raw().unwrap()
    }
}

/// Initializes the global keyboard buffer.
///
/// # Safety
/// - Keyboard buffer MUST be called before others
pub fn init() {
    without_interrupts(|| {
        EVENT_QUEUE.write().call_once(|| EventQueue::new());
    });
}

/// Puts a event into a buffer (called from driver).
pub fn put(event: InputEvent) {
    without_interrupts(|| {
        EVENT_QUEUE.write().get_mut().unwrap().push(event);
    });
}

/// Gets a character from a buffer.
pub fn get() -> InputEvent {
    without_interrupts(|| {
        EVENT_QUEUE.write().get_mut().unwrap().get()
    })
}