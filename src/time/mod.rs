#[inline]
pub fn tick() {
    noct_time::systemclock::tick();

    noct_sched::schedule();
}
