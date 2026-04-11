use crate::sched;

#[inline]
pub fn tick() {
    noct_time::systemclock::tick();
    
    sched::schedule();
}