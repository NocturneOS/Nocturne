use noct_io::error::Error;
use noct_logger::qemu_log;
use noct_mem::paging::PageFlags;

use crate::mem::usermem::verify_ptr;

pub fn sbrk(increment: usize, _: usize, _: usize, _: usize, _: usize) -> Option<usize> {
    let process = &noct_sched::this_thread().process;

    let increment = increment as isize;

    let mut address_space_lock = unsafe { process.address_space.pseudo_lock() };
    let mut lock = process.heap.lock();

    let heap = lock.as_mut().expect("Heap was uninitialized!");

    let next_value = heap.sbrk(&mut address_space_lock, increment);

    match next_value {
        Ok(next_address) => {
            qemu_log!(
                "sbrk: {}{}: new address is (start: {:#x?}; end: {:#x?}; max: {:#x?})",
                if increment.is_negative() { "-" } else { "" },
                increment,
                heap.base(),
                heap.end(),
                heap.max()
            );

            Some(next_address)
        }
        Err(e) => {
            qemu_log!("sbrk: +{}: fail ({e:?})", increment);

            noct_sched::set_error(noct_io::error::Error::MemoryError as _);

            None
        }
    }
}

pub fn mrequest(bytes_count: usize, _: usize, _: usize, _: usize, _: usize) -> Option<usize> {
    let process = &noct_sched::this_thread().process;

    // AddressSpace inside Process has a pseudo-lock, so I have to disable interrupts for a while.
    let address: Option<usize> = noct_tools::without_interrupts::without_interrupts(|| unsafe {
        process
            .address_space
            .pseudo_lock()
            .alloc_virt_region(bytes_count)
    });

    let Some(address) = address else {
        qemu_log!("mrequest: failed to allocate {bytes_count} bytes");

        noct_sched::set_error(noct_io::error::Error::MemoryError as _);

        return None;
    };

    let alloc = noct_tools::without_interrupts::without_interrupts(|| unsafe {
        process
            .address_space
            .pseudo_lock()
            .alloc_map_multiple_pages(
                address,
                bytes_count,
                PageFlags::Writeable | PageFlags::Userspace,
            )
    });

    if let Err(e) = alloc {
        // Deallocate region.
        noct_tools::without_interrupts::without_interrupts(|| unsafe {
            process
                .address_space
                .pseudo_lock()
                .free_virt_region(address)
        });

        qemu_log!("mrequest: failed to allocate {bytes_count} bytes (error: {e:?})");

        noct_sched::set_error(noct_io::error::Error::MemoryError as _);

        return None;
    }

    core::mem::forget(alloc);

    Some(address)
}

pub fn mfree(
    addr: usize,
    /* bytes_count */ _: usize,
    _: usize,
    _: usize,
    _: usize,
) -> Option<usize> {
    let addr = super::convert_err(|| {
        let verified_ptr = verify_ptr::<u8>(addr).map(|x| x.addr());

        verified_ptr.ok_or(Error::MemoryError)
    })?;

    // Align bytes count to page size.
    // let bytes_count = noct_tools::align_value(bytes_count, noct_mem::get_page_size());

    let process = &noct_sched::this_thread().process;

    // AddressSpace inside Process has a pseudo-lock, so I have to disable interrupts for a while.
    let freed = noct_tools::without_interrupts::without_interrupts(|| unsafe {
        process.address_space.pseudo_lock().free_virt_region(addr)
    });

    if !freed {
        qemu_log!("mfree: tried to free an unknown region at {addr:#x?}");

        noct_sched::set_error(Error::MemoryError as _);

        return None;
    }

    None
}
