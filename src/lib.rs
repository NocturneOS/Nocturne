#![no_std]

use core::panic::PanicInfo;

use crate::arch::x86::video::bios_text_vga::{clear_screen, test_write};

mod arch;
mod io;
mod mem;
mod spec;
mod time;
mod interrupts;

fn kmain() -> ! {
    clear_screen();
    test_write();
    
    qemu_log!("It works!");

    loop { arch::halt(); }
}

#[panic_handler]
fn __panic_handler(info: &PanicInfo) -> ! {
    qemu_log!("Kernel panicked: {:?} {:?}", info.location(), info.message());
    loop {}
}