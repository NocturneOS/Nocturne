use core::ffi::c_char;

use crate::mem::usermem::{verify_ptr, verify_ptr_range, verify_ptr_range_mut};

pub fn getcwd(buf: usize, size: usize, _: usize, _: usize, _: usize) -> Option<usize> {
    let Some(ptr) = verify_ptr_range_mut::<c_char>(buf, size) else {
        noct_sched::set_error(noct_io::error::Error::MemoryError as _);

        return Some(0);
    };

    let proc = noct_sched::this_process();
    let cwd = proc.cwd();

    unsafe { cwd.as_ptr().cast::<c_char>().copy_to(ptr, cwd.len()) };

    Some(buf)
}
