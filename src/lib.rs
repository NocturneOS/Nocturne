#![no_std]

use core::{alloc::{GlobalAlloc, Layout}, panic::PanicInfo};

use alloc::vec::Vec;

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
    
    // arch::halt_forever();    

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
