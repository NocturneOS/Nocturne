#![no_std]

pub mod interrupt_locker;
pub mod without_interrupts;

#[inline]
pub fn align_value(value: usize, alignment: usize) -> usize {
    if value.is_multiple_of(alignment) {
        return value;
    }

    (value + alignment - 1) & !(alignment - 1)
}

#[inline]
pub fn align_down(addr: usize, align: usize) -> usize {
    addr & !(align - 1)
}

pub fn measure_time_cpu<F, R>(f: F) -> (R, u64)
where
    F: FnOnce() -> R,
{
    let start = unsafe { x86::time::rdtsc() };

    let res = f();

    let end = unsafe { x86::time::rdtsc() };

    (res, end - start)
}

pub fn measure_time_timer<F, R>(f: F) -> (R, u128)
where
    F: FnOnce() -> R,
{
    let start = noct_time::systemclock::get_uptime_millis();

    let res = f();

    let end = noct_time::systemclock::get_uptime_millis();

    (res, end - start)
}