use noct_logger::qemu_log;

pub fn sbrk(increment: usize, _: usize, _: usize, _: usize, _: usize) -> Option<usize> {
    let process = &noct_sched::this_thread().process;

    let increment = increment as isize;
    
    let address_space_lock = unsafe { process.address_space.get_mut() };
    let mut lock = process.heap.lock();
    
    let heap = lock
        .as_mut()
        .expect("Heap was uninitialized!");

    let next_value = heap
        .sbrk(address_space_lock, increment);

    match next_value {
        Ok(next_address) => {
            qemu_log!("sbrk: {}{}: new address is (start: {:#x?}; end: {:#x?}; max: {:#x?})", if increment.is_negative() { "-" } else { "" }, increment, heap.base(), heap.end(), heap.max());

            Some(next_address)
        },
        Err(e) => {
            qemu_log!("sbrk: +{}: fail ({e:?})", increment);

            noct_sched::set_error(noct_io::error::Error::MemoryError as _);

            None
        },
    }
}
