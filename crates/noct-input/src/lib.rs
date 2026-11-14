#![no_std]
#![allow(static_mut_refs)]

extern crate alloc;

use alloc::{collections::vec_deque::VecDeque};

use crate::{event::InputEvent, ring::EventRing};

use core::fmt::Debug;

pub mod event;
pub mod keyboard;
pub mod mouse;
pub mod ring;

const INPUT_RING_SIZE: usize = 128;

static INPUT_RING: EventRing<INPUT_RING_SIZE> = EventRing::new();

/// Queues an event from IRQ context.
///
/// This performs no allocation and takes no locks.
pub fn push_event(event: InputEvent) -> bool {
    INPUT_RING.push(event)
}

/// Pops an event in thread context (the input dispatcher).
pub fn pop_event() -> Option<InputEvent> {
    INPUT_RING.pop()
}

pub fn input_pending() -> bool {
    !INPUT_RING.is_empty()
}

/// Global keyboard buffer (kernel-wide). Used everywhere.
// static EVENT_QUEUE: RwLock<spin::Once<EventQueue>> = RwLock::new(Once::new());

/// A definition of Keyboard buffer. It's just a pre-allocated vector, but functionality can be extended soon and new fields may be added.
pub struct EventQueue {
    buffer: VecDeque<InputEvent>,
}

impl Debug for EventQueue {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("EventQueue").field("length", &self.buffer.len()).finish()
    }
}

impl EventQueue {
    const QUEUE_SIZE: usize = 1024;

    /// Creates a new event queue instance.
    pub fn new() -> Self {
        let buffer = VecDeque::with_capacity(Self::QUEUE_SIZE);

        Self { buffer }
    }

    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
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
        self.buffer.pop_front()
    }
}

// /// Initializes the global keyboard buffer.
// ///
// /// # Safety
// /// - Keyboard buffer MUST be called before others
// pub fn init() {
//     without_interrupts(|| {
//         EVENT_QUEUE.write().call_once(|| EventQueue::new());
//     });
// }

// /// Puts a event into a buffer (called from driver).
// pub fn put(event: InputEvent) {
//     without_interrupts(|| {
//         EVENT_QUEUE.write().get_mut().unwrap().push(event);
//     });
// }

// /// Gets a character from a buffer.
// pub fn get() -> InputEvent {
//     loop {
//         if let Some(event) = without_interrupts(|| {
//             EVENT_QUEUE.write().get_mut().unwrap().get_raw()
//         }) {
//             return event;
//         }

//         // TODO: Uncomment that when SMP is implemented.
//         // core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::Acquire);

//         noct_sched::yield_now();
//     }
// }