#![no_std]

use core::panic::PanicInfo;

use crate::arch::x86::video::bios_text_vga::{clear_screen, test_write};

mod arch;
mod io;
mod interrupts;
mod mem;
mod spec;
mod sys;
mod time;
mod unwind;
mod tools;

extern "C" fn kmain() -> ! {
    clear_screen();
    test_write();
    
    qemu_log!("It works!");

    loop { arch::halt(); }
}

#[panic_handler]
fn __panic_handler(info: &PanicInfo) -> ! {
    if let Some(loc) = info.location() {
        qemu_log!("Kernel panicked at {}:{}:{}: {:#?}", loc.file(), loc.line(), loc.column(), info.message());
    } else {
        qemu_log!("Kernel panicked: {:?}", info.message());
    }

    unsafe { unwind::backtrace() };

    arch::halt_forever()
}