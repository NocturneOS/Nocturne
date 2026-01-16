use lazy_static::lazy_static;
use spin::Mutex;

lazy_static! {
    static ref TIME_TICKS: Mutex<u128> = 0.into();
    static ref TICKING_FREQUENCY: Mutex<usize> = 1.into();
}

#[inline]
pub fn set_timer_frequency(freq: usize) {
    *TICKING_FREQUENCY.lock() = freq;
}

#[inline]
pub fn tick() {
    *TIME_TICKS.lock() += 1;
}

#[inline]
pub fn get_uptime_ticks() -> u128 {
    *TIME_TICKS.lock()
}

#[inline]
pub fn get_uptime_nanos() -> u128 {
    let ticks = *TIME_TICKS.lock();
    let freq = *TICKING_FREQUENCY.lock();

    (ticks * 1_000_000_000) / freq as u128
}