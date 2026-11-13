use core::{cell::UnsafeCell, mem::MaybeUninit, sync::atomic::{AtomicUsize, Ordering}};

use crate::event::InputEvent;

// This is my first usage of lock-free structures, so there are a lot of comments describing obvious
// things.

/// A fixed-size, allocation-free, lock-free single-producer/single-consumer ring.
///
/// The keyboard IRQ is the producer and the kernel input dispatcher thread is
/// the consumer. 
/// This is made lock-free because IRQ shouldn't take any mutexes.
pub struct EventRing<const N: usize> {
    buffer: [UnsafeCell<MaybeUninit<InputEvent>>; N],
    /// Index of the next slot to write.
    head: AtomicUsize,
    /// Index of the next slot to read.
    tail: AtomicUsize,
}

unsafe impl<const N: usize> Sync for EventRing<N> {}

impl<const N: usize> EventRing<N> {
    pub const fn new() -> Self {
        Self {
            buffer: [const { UnsafeCell::new(MaybeUninit::uninit()) }; N],
            head: AtomicUsize::new(0),
            tail: AtomicUsize::new(0),
        }
    }

    /// Pushes an event. Returns `false` when the ring is full.
    pub fn push(&self, event: InputEvent) -> bool {
        let head = self.head.load(Ordering::Relaxed);

        // Wrap the counter when N is reached.
        let next = (head + 1) % N;

        //        DDDDDDDDDDDDD
        // head   -----^
        // tail         ^------
        //
        // The selected range ^---^ is used area. (distance between head and tail is a used ring length).
        // If head + 1 == tail, then it means that we reached the beginning of the ring, so we can't
        // push elements.
        //
        // NOTE: Tail is used for reads, head if used for writes
        if next == self.tail.load(Ordering::Acquire) {
            return false;
        }

        // SAFETY: `head` is only advanced by the single producer after the
        // slot has been initialized, and the consumer never reads this slot
        // until it observes the new `head`.
        unsafe {
            (*self.buffer[head].get()).write(event);
        }

        self.head.store(next, Ordering::Release);

        true
    }

    /// Pops the oldest event, or `None` when the ring is empty.
    pub fn pop(&self) -> Option<InputEvent> {
        let tail = self.tail.load(Ordering::Relaxed);

        //        DDDDDDDDDDDDD
        // head         -^
        // tail        ^-
        //
        // The selected range ^---^ is used area. (distance between head and tail is a used ring length).
        // If tail == head, it means that there are no elements to read.
        //
        // NOTE: Tail is used for reads, head if used for writes
        if tail == self.head.load(Ordering::Acquire) {
            return None;
        }

        // SAFETY: `tail` points at a slot that was initialized by the
        // producer and not yet consumed.
        let event = unsafe { (*self.buffer[tail].get()).assume_init_read() };

        self.tail.store((tail + 1) % N, Ordering::Release);

        Some(event)
    }

    pub fn is_empty(&self) -> bool {
        self.tail.load(Ordering::Acquire) == self.head.load(Ordering::Acquire)
    }
}
