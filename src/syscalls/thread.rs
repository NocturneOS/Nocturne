use noct_io::error::Error;
use noct_sched::thread::{ThreadFlags, ThreadPriority};

use crate::mem::usermem::{verify_ptr_range, verify_ptr_range_mut};

pub fn create(
    entry_point: usize,
    stack_bottom: usize,
    stack_size: usize,
    arg: usize,
    _: usize,
) -> Result<usize, Error> {
    // TODO: The stack memory block should come from user, not from kernel!
    // TODO: Check `entry_point` pointer validity!!!

    let _ = verify_ptr_range_mut::<u8>(stack_bottom, stack_size).ok_or(Error::MemoryError)?;

    let thread = noct_sched::create_thread(
        noct_sched::this_process(),
        unsafe { core::mem::transmute(entry_point) },
        stack_size,
        ThreadPriority::Medium,
        ThreadFlags::User,
        Some(stack_bottom),
        &[arg]
    );

    thread.ok_or(Error::InvalidArgument)
}
