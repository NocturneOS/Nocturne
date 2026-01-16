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
    qemu_print!("It works!");

    clear_screen();
    test_write();

    arch::halt();
}

#[panic_handler]
fn __panic_handler(info: &PanicInfo) -> ! {
    loop {}
}