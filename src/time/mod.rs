use lazy_static::lazy_static;
use spin::Mutex;

lazy_static! {
    static ref TIME_TICKS: Mutex<u128> = 0.into();
}

#[inline]
pub fn tick() {
    *TIME_TICKS.lock() += 1;
}

#[inline]
pub fn get_uptime_ticks() -> u128 {
    *TIME_TICKS.lock()
}