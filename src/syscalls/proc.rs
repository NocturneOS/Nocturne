use core::{ffi::c_char, sync::atomic::Ordering};

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

        const Blocking = 1 << 6;
    }
}

pub fn run(path_ptr: usize, arguments_ptr: usize, flags: usize, _: usize, _: usize) -> Option<usize> {
    let path = crate::mem::usermem::verify_ptr::<c_char>(path_ptr)?;
    let args = crate::mem::usermem::verify_ptr::<*const c_char>(path_ptr)?;

    todo!("Implement running processes!")
}

pub fn waitpid(pid: usize, _: usize, _: usize, _: usize, _: usize) -> Option<usize> {
    let Some(ph) = noct_sched::get_process_handle(pid) else {
        let this_thread = noct_sched::this_thread();

        this_thread.last_error.store(Error::InvalidHandle as u32 as usize, Ordering::Release);
        
        return None;
    };

    let code = noct_sched::waitpid(&ph);

    code.map(|x| x as usize)
}

pub fn yield_now(_: usize, _: usize, _: usize, _: usize, _: usize) -> Option<usize> {
    noct_sched::yield_now();
    
    None
}