use noct_logger::qemu_log;

pub fn exit(_: usize, _: usize, _: usize, _: usize, _: usize) -> Option<usize> {
    noct_sched::thread_exit()
}

pub fn process_exit(exitcode: usize, _: usize, _: usize, _: usize, _: usize) -> Option<usize> {
    qemu_log!("Process exit! Exit code: {exitcode}");

    noct_sched::process_exit(exitcode as u32);

    None
}