use crate::interrupt_locker::InterruptLocker;

pub fn without_interrupts<T>(f: impl FnOnce() -> T) -> T {
    let locker = InterruptLocker::lock();

    let result = f();

    drop(locker);

    result
}
