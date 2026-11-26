use core::{
    ffi::{CStr, c_char},
    sync::atomic::Ordering,
};

use alloc::vec::Vec;
use noct_elfloader::LoadError;
use noct_io::error::Error;

use bitflags::bitflags;

bitflags! {
    pub struct ProgramRunFlags: u32 {
        const NoStdin  = 1 << 0;
        const NoStdout = 1 << 1;
        const NoStderr = 1 << 2;

        const PipedStdin  = 1 << 3;
        const PipedStdout = 1 << 4;
        const PipedStderr = 1 << 5;
    }
}

/// Spawns a new process.
///
/// Returns -errno if ELF loading error happened.
/// Returns a new process' PID otherwise. (errno is set to 0)
pub fn run(
    path_ptr: usize,
    arguments_ptr: usize,
    args_len: usize,
    flags: usize,
    _: usize,
) -> Result<usize, Error> {
    // XXX: Think on how to verify path.
    let path = { crate::mem::usermem::verify_ptr::<c_char>(path_ptr).ok_or(Error::MemoryError) }?;
    let args = {
        crate::mem::usermem::verify_ptr_range::<*const c_char>(arguments_ptr, args_len)
            .ok_or(Error::MemoryError)
    }?;

    let path = unsafe {
        CStr::from_ptr(path)
            .to_str()
            .map_err(|_| Error::InvalidArgument)
    }?;

    let arguments = unsafe { core::slice::from_raw_parts(args, args_len) };

    let arguments_str = arguments
        .into_iter()
        .map(|&x| unsafe { CStr::from_ptr(x) }.to_str().unwrap())
        .collect::<Vec<_>>();

    let flags = ProgramRunFlags::from_bits_truncate(flags as _);

    let hdl = match noct_elfloader::spawn(path, &arguments_str) {
        Ok(hdl) => Ok(hdl),
        Err(LoadError::System(e)) => Err(e as _),
        Err(LoadError::InvalidELFType | LoadError::UnsupportedArchitecture) => {
            Err(Error::ExecFormat as _)
        }
        Err(_) => Err(Error::InvalidArgument as _),
    }?;

    Ok(hdl.pid)
}

pub fn waitpid(pid: usize, _: usize, _: usize, _: usize, _: usize) -> Result<usize, Error> {
    // TODO: Parse the status pointer and options (WNOHANG) once the ABI is settled.
    match noct_sched::waitpid(pid) {
        Ok(code) => Ok(code as usize),
        Err(noct_sched::WaitError::NoChild) => Err(Error::NoChild),
        Err(noct_sched::WaitError::SelfWait) => Err(Error::InvalidArgument),
    }
}

pub fn getpid(_: usize, _: usize, _: usize, _: usize, _: usize) -> Result<usize, Error> {
    Ok(noct_sched::this_process().id)
}

pub fn yield_now(_: usize, _: usize, _: usize, _: usize, _: usize) -> Result<usize, Error> {
    noct_sched::yield_now();

    Ok(0)
}
