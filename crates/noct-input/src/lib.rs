#![no_std]
#![allow(static_mut_refs)]

extern crate alloc;

use alloc::vec::Vec;
use spin::{Once, RwLock};

pub mod kbd;

/// Global keyboard buffer (kernel-wide). Used everywhere.
static KEYBOARD_BUFFER: RwLock<spin::Once<KeyboardBuffer>> = RwLock::new(Once::new());

/// A definition of Keyboard buffer. It's just a pre-allocated vector, but functionality can be extended soon and new fields may be added.
pub struct KeyboardBuffer {
    buffer: Vec<u32>,
}

impl Default for KeyboardBuffer {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyboardBuffer {
    /// Creates a new keyboard buffer instance.
    pub fn new() -> Self {
        let buffer = Vec::<u32>::with_capacity(512);

        KeyboardBuffer { buffer }
    }

    /// Push a character into a buffer.
    pub fn push(&mut self, character: u32) {
        let bind = &mut self.buffer;

        bind.push(character);
    }

    /// Pop a character from a buffer, just calls for Vec::pop().
    pub fn get_raw(&mut self) -> Option<u32> {
        let bind = &mut self.buffer;
        
        bind.pop()
    }

    /// Polls for a character from a buffer.
    pub fn get(&mut self) -> u32 {
        while self.buffer.is_empty() {
            // Idk what this function does, but it works! (Not throwing polling away)
            core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);

            noct_sched::yield_now();
        }

        self.get_raw().unwrap()
    }
}

/// Initializes the global keyboard buffer.
///
/// # Safety
/// - Keyboard buffer MUST be called before others
pub unsafe fn init() {
    KEYBOARD_BUFFER.write().call_once(|| KeyboardBuffer::new());
}

/// Puts a character into a buffer (called from driver).
pub fn put(character: u32) {
    KEYBOARD_BUFFER.write().get_mut().unwrap().push(character);
}

/// Gets a character from a buffer.
pub fn get() -> u32 {
    KEYBOARD_BUFFER.write().get_mut().unwrap().get()
}