use core::sync::atomic::Ordering;

use noct_io::error::Error;
use noct_logger::qemu_log;

pub fn exit(_: usize, _: usize, _: usize, _: usize, _: usize) -> Result<usize, Error> {
    {
        let process = &noct_sched::this_thread().process;

        // If this is the last thread, the process is going away and its input
        // listeners must not remain in the dispatcher list.
        if process.thread_count.load(Ordering::Acquire) == 1 {
            noct_input_dispatcher::unregister_process(process.id);
        }
    }

    noct_sched::thread_exit()
}

pub fn process_exit(
    exitcode: usize,
    _: usize,
    _: usize,
    _: usize,
    _: usize,
) -> Result<usize, Error> {
    qemu_log!("Process exit! Exit code: {exitcode}");

    let process = &noct_sched::this_thread().process;

    noct_input_dispatcher::unregister_process(process.id);

    noct_sched::process_exit(exitcode as u32)
}
