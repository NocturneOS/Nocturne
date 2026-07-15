pub fn sbrk(increment: usize, _: usize, _: usize, _: usize, _: usize) -> Option<usize> {
    let process = &noct_sched::this_thread().process;

    let mut address_space_lock = unsafe { process.address_space.get_mut() };
    let mut lock = process.heap.lock();

    let next_value = lock
        .as_mut()
        .expect("Heap was uninitialized!")
        .sbrk(address_space_lock, increment as isize);

    match next_value {
        Ok(next_address) => Some(next_address),
        Err(_) => {
            noct_sched::set_error(noct_io::error::Error::MemoryError as _);

            None
        },
    }
}
