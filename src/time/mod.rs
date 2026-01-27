use core::cell::UnsafeCell;

use lazy_static::lazy_static;
use spin::Mutex;

use crate::{sched, tools::pseudosync::PseudoSync};

lazy_static! {
    static ref TIME_TICKS: PseudoSync<UnsafeCell<u128>> = PseudoSync::new(UnsafeCell::new(0));
    static ref TICKING_FREQUENCY: Mutex<usize> = 1.into();
}

#[inline]
pub fn set_timer_frequency(freq: usize) {
    *TICKING_FREQUENCY.lock() = freq;
}

#[inline]
pub fn tick() {
    let current_ticks = unsafe { TIME_TICKS.as_ref().get().read() };

    unsafe { TIME_TICKS.as_ref().get().write(current_ticks + 1) };

    sched::schedule();
}

#[inline]
pub fn get_uptime_ticks() -> u128 {
    unsafe { TIME_TICKS.as_ref().get().read() }
}

#[inline]
pub fn get_uptime_nanos() -> u128 {
    let ticks = get_uptime_ticks();
    let freq = *TICKING_FREQUENCY.lock();

    (ticks * 1_000_000_000) / freq as u128
}
