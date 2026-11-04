use core::ffi::{CStr, c_char};

use noct_io::error::Error;

use crate::syscalls::convert_err;

pub fn opendir(path: usize, _: usize, _: usize, _: usize, _: usize) -> Option<usize> {
    let path = convert_err(|| {
        let ptr = crate::mem::usermem::verify_ptr::<c_char>(path).ok_or(Error::MemoryError)?;

        Ok(unsafe { CStr::from_ptr(ptr).to_string_lossy() })
    })?;

    let dir = convert_err(|| noct_fs::open_directory(&path))?;

    let fd = {
        let proc = noct_sched::this_process();

        let mut bind = proc.resources.lock();

        bind.make(noct_descriptor::ResourceDescriptor::DirectoryHandle(dir)).id()
    };

    Some(fd)
}