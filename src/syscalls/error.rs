use core::sync::atomic::Ordering;

use noct_io::error::Error;

pub fn geterror(_: usize, _: usize, _: usize, _: usize, _: usize) -> Result<usize, Error> {
    let this_thread = noct_sched::this_thread();
    
    let errno = this_thread.last_error.load(Ordering::Acquire);

    Ok(errno as _)
}