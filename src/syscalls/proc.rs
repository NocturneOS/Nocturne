use core::{
    ffi::{CStr, c_char},
    sync::atomic::Ordering,
};

use alloc::vec::Vec;
use noct_elfloader::LoadError;
use noct_io::error::Error;

use bitflags::bitflags;

use crate::syscalls::convert_err;

bitflags! {
    pub struct ProgramRunFlags: u32 {
        const NoStdin  = 1 << 0;
        const NoStdout = 1 << 1;
        const NoStderr = 1 << 2;

        const PipedStdin  = 1 << 3;
        const PipedStdout = 1 << 4;
        const PipedStderr = 1 << 5;

        const Blocking = 1 << 6;
    }
}

pub fn run(
    path_ptr: usize,
    arguments_ptr: usize,
    args_len: usize,
    flags: usize,
    _: usize,
) -> Option<usize> {
    // XXX: Think on how to verify path.
    let path = convert_err(|| {
        crate::mem::usermem::verify_ptr::<c_char>(path_ptr).ok_or(Error::MemoryError)
    })?;
    let args = convert_err(|| {
        crate::mem::usermem::verify_ptr_range::<*const c_char>(arguments_ptr, args_len)
            .ok_or(Error::MemoryError)
    })?;

    let path = convert_err(|| unsafe {
        CStr::from_ptr(path)
            .to_str()
            .map_err(|_| Error::InvalidArgument)
    })?;

    let arguments = unsafe { core::slice::from_raw_parts(args, args_len) };

    let arguments_str = arguments
        .into_iter()
        .map(|&x| unsafe { CStr::from_ptr(x) }.to_str().unwrap())
        .collect::<Vec<_>>();

    let hdl = match noct_elfloader::spawn(path, &arguments_str) {
        Ok(hdl) => hdl,
        Err(LoadError::System(e)) => {
            noct_sched::set_error(e as _);

            return Some(0);
        }
        Err(LoadError::InvalidELFType | LoadError::UnsupportedArchitecture) => {
            noct_sched::set_error(Error::ExecFormat as _);

            return Some(0);
        }
        Err(_) => {
            noct_sched::set_error(Error::InvalidArgument as _);

            return Some(0);
        }
    };

    Some(hdl.pid)
}

pub fn waitpid(pid: usize, _: usize, _: usize, _: usize, _: usize) -> Option<usize> {
    let ph = convert_err(|| noct_sched::get_process_handle(pid).ok_or(Error::MemoryError))?;

    let code = noct_sched::waitpid(&ph);

    Some(code as usize)
}

pub fn yield_now(_: usize, _: usize, _: usize, _: usize, _: usize) -> Option<usize> {
    noct_sched::yield_now();

    None
}
