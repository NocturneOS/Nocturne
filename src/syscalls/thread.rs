use noct_io::error::Error;
use noct_sched::thread::{ThreadFlags, ThreadPriority};

pub fn create(
    entry_point: usize,
    stack_size: usize,
    arg: usize,
    _: usize,
    _: usize,
) -> Result<usize, Error> {
    // TODO: The stack memory block should come from user, not from kernel!
    // TODO: Check `entry_point` pointer validity!!!

    let thread = noct_sched::create_thread(
        noct_sched::this_process(),
        unsafe { core::mem::transmute(entry_point) },
        stack_size,
        ThreadPriority::Medium,
        ThreadFlags::User,
        &[arg]
    );

    thread.ok_or(Error::InvalidArgument)
}
