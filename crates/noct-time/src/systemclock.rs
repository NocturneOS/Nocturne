use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use lazy_static::lazy_static;
use noct_sync::pseudosync::PseudoSync;

static TIME_TICKS: AtomicU64 = AtomicU64::new(0);
static TICKING_FREQUENCY: AtomicUsize = AtomicUsize::new(1);

#[inline]
pub fn set_timer_frequency(freq: usize) {
    TICKING_FREQUENCY.store(freq, Ordering::Release);
}

#[inline]
pub fn tick() {
    TIME_TICKS.fetch_add(1, Ordering::Release);
}

#[inline]
pub fn get_uptime_ticks() -> u128 {
    TIME_TICKS.load(Ordering::Relaxed) as _
}

#[inline]
pub fn get_uptime_nanos() -> u128 {
    let ticks = get_uptime_ticks();
    let freq = TICKING_FREQUENCY.load(Ordering::Relaxed);

    (ticks * 1_000_000_000) / freq as u128
}

#[inline]
pub fn get_uptime_millis() -> u128 {
    get_uptime_nanos() / 1_000_000
}

#[inline]
pub fn nanos_to_ticks(nanos: u128) -> u128 {
    let freq = TICKING_FREQUENCY.load(Ordering::Relaxed);

    (nanos * freq as u128) / 1_000_000_000
}
