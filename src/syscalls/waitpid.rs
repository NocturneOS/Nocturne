use core::sync::atomic::Ordering;

use noct_io::error::Error;

pub fn waitpid(pid: usize, _: usize, _: usize, _: usize, _: usize) -> Option<usize> {
    let Some(ph) = noct_sched::get_process_handle(pid) else {
        let this_thread = noct_sched::this_thread();

        this_thread.last_error.store(Error::InvalidHandle as u32 as usize, Ordering::Release);
        
        return None;
    };

    let code = noct_sched::waitpid(&ph);

    code.map(|x| x as usize)
}