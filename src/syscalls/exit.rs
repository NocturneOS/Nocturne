use noct_logger::qemu_log;

pub fn exit(exitcode: usize, _: usize, _: usize, _: usize, _: usize) -> Option<usize> {
    qemu_log!("Process exit! Exit code: {exitcode}");

    noct_sched::thread_exit()
}