use core::sync::atomic::Ordering;

pub fn geterror(_: usize, _: usize, _: usize, _: usize, _: usize) -> Option<usize> {
    let this_thread = noct_sched::this_thread();
    
    let errno = this_thread.last_error.load(Ordering::Acquire);

    Some(errno as _)
}