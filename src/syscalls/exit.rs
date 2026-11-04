use noct_io::error::Error;
use noct_logger::qemu_log;

pub fn exit(_: usize, _: usize, _: usize, _: usize, _: usize) -> Result<usize, Error> {
    noct_sched::thread_exit()
}

pub fn process_exit(exitcode: usize, _: usize, _: usize, _: usize, _: usize) -> Result<usize, Error> {
    qemu_log!("Process exit! Exit code: {exitcode}");

    noct_sched::process_exit(exitcode as u32)
}