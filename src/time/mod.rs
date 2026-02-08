use core::cell::UnsafeCell;

use lazy_static::lazy_static;
use spin::Mutex;

use crate::{qemu_log, sched, tools::pseudosync::PseudoSync};

lazy_static! {
    static ref TIME_TICKS: PseudoSync<u128> = PseudoSync::new(0);
    static ref TICKING_FREQUENCY: PseudoSync<usize> = 1.into();
}

#[inline]
pub fn set_timer_frequency(freq: usize) {
    *unsafe { TICKING_FREQUENCY.get_mut() } = freq;
}

#[inline]
pub fn tick() {
    unsafe {
        *TIME_TICKS.get_mut() += 1;
    }

    sched::schedule();
}

#[inline]
pub fn get_uptime_ticks() -> u128 {
    *TIME_TICKS.get()
}

#[inline]
pub fn get_uptime_nanos() -> u128 {
    let ticks = get_uptime_ticks();
    let freq = *TICKING_FREQUENCY.get();

    (ticks * 1_000_000_000) / freq as u128
}

#[inline]
pub fn nanos_to_ticks(nanos: u128) -> u128 {
    let freq = *TICKING_FREQUENCY.get();

    (nanos * freq as u128) / 1_000_000_000
}