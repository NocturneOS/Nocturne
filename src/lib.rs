#![no_std]
#![feature(linked_list_retain)]

use core::{panic::PanicInfo, time::Duration};

use alloc::sync::Arc;
use noct_logger::qemu_log;

use crate::{
    arch::mem::paging::PageFlags,
    sched::{
        KERNEL_THREAD_DEFAULT_STACK_SIZE,
        thread::{ThreadFlags, ThreadPriority},
    },
};

mod arch;
mod mem;
mod sched;
mod time;
mod unwind;

extern crate alloc;

// This entry point is called from `arch_init`.
extern "C" fn kmain() -> ! {
    // Now `__arch_init` initialized paging and PMM for us.
    // To make kernel fully initialized we should initialize heap.

    mem::heap::init();

    sched::init();

    // {
    // qemu_log!("Creating 32 processes...");

    // let procs: [_; 32] = core::array::from_fn(|_| crate::sched::create_process("proc", "?"));

    // qemu_log!("32 processes have been created!");

    // core::mem::drop(procs);

    // let proc = crate::sched::this_process();

    // for _ in 0..32 {
    //     crate::sched::create_thread(Arc::clone(&proc), move || {
    //         let id = crate::sched::this_thread_id();

    //         loop {
    //             qemu_log!("Hi thread #{}", id);
    //             crate::sched::sleep(Duration::from_millis((id * 40) as _));
    //         }
    //     }, KERNEL_THREAD_DEFAULT_STACK_SIZE, ThreadPriority::Low, ThreadFlags::empty());
    // }
    // }

    // loop {}

    noct_pci::scan();

    for i in noct_pci::devices().iter() {
        qemu_log!(
            "[{}.{}.{}]: ({}:{}): {:04x}:{:04x}",
            i.bus,
            i.slot,
            i.function,
            i.class,
            i.subclass,
            i.vendor,
            i.device
        );
    }

    {
        arch::mem::paging::map_pages(0xf_0000, 0xf_0000, 0x1_0000, PageFlags::Present);

        if let Some(smbios) = noct_smbios::find_smbios() {
            let values = smbios.scan();

            for i in values {
                qemu_log!("{i:#?}");
            }
        }

        arch::mem::paging::unmap_pages(0xf_0000, 0x1_0000);
    }

    noct_ps2::init();

    // clear_screen();
    // test_write();

    crate::arch::x86::dev::ata::init();

    for (idx, disk) in noct_diskman::disk_list().iter().enumerate() {
        qemu_log!(
            "#{}: id={}, name={}, type={:?}, capacity={} blocks {} bytes each, is_partition={}",
            idx,
            disk.id,
            disk.name,
            disk.drive_type,
            disk.capacity.unwrap(),
            disk.block_size.unwrap(),
            disk.is_partition
        );
    }

    qemu_log!("It works!");

    loop {
        arch::halt();
    }
}

#[panic_handler]
fn __panic_handler(info: &PanicInfo) -> ! {
    noct_interrupts::cpu::disable_interrupts();

    if let Some(loc) = info.location() {
        qemu_log!(
            "Kernel panicked at {}:{}:{}: {:#?}",
            loc.file(),
            loc.line(),
            loc.column(),
            info.message()
        );
    } else {
        qemu_log!("Kernel panicked: {:?}", info.message());
    }

    unsafe { unwind::backtrace() };

    arch::halt_forever()
}
