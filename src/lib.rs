#![no_std]

use core::panic::PanicInfo;

use crate::arch::x86::video::bios_text_vga::{clear_screen, test_write};

mod arch;

#[unsafe(no_mangle)]
extern "C" fn kmain() {
    for i in "It works!".bytes() {
        unsafe {
            x86::io::outb(0x3f8, i as u8);
        }
    }

    clear_screen();
    test_write();

    loop {}
}

#[panic_handler]
fn __panic_handler(info: &PanicInfo) -> ! {
    loop {}
}