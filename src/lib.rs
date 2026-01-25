#![no_std]

use core::{alloc::{GlobalAlloc, Layout}, panic::PanicInfo};

use alloc::vec;

use crate::{arch::x86::video::bios_text_vga::{clear_screen, test_write}, sys::info::info};

mod arch;
mod interrupts;
mod io;
mod mem;
mod spec;
mod sys;
mod time;
mod tools;
mod unwind;

extern crate alloc;

// This entry point is called from `arch_init`.
extern "C" fn kmain() -> ! {
    // Now `arch_init` initialized paging and PMM for us.
    // To make kernel fully initialized we should initialize heap.

    mem::heap::init();

    unsafe {
        let ptr = alloc::alloc::alloc_zeroed(Layout::from_size_align(10, 4).unwrap());
        let ptr2 = alloc::alloc::alloc_zeroed(Layout::from_size_align(20, 4).unwrap());
        let ptr3 = alloc::alloc::alloc_zeroed(Layout::from_size_align(30, 4).unwrap());
        let ptr4 = alloc::alloc::alloc_zeroed(Layout::from_size_align(40, 4).unwrap());
        let ptr5 = alloc::alloc::alloc_zeroed(Layout::from_size_align(50, 4).unwrap());
        let ptr6 = alloc::alloc::alloc_zeroed(Layout::from_size_align(60, 4).unwrap());

        alloc::alloc::dealloc(ptr4, Layout::from_size_align(40, 4).unwrap());
    }
    
    mem::heap::dump();

    qemu_log!("OK!");
    
    arch::halt_forever();

    // let mut what = Vec::<i32>::new();

    // for i in 0..1024 {
    //     qemu_log!("Added: {i}");
    //     what.push(i);
    // }

    // qemu_log!("{:?}", what);

    clear_screen();
    test_write();

    qemu_log!("It works!");

    loop {
        arch::halt();
    }
}

#[panic_handler]
fn __panic_handler(info: &PanicInfo) -> ! {
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
