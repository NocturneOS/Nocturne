use core::ptr::{addr_of, addr_of_mut};

use crate::qemu_log;

unsafe extern "C" {
    // Comes from src/arch/x86/asm/init.s
    static mut boot_page_directory: [u32; 1024];
}

pub fn page_directory() -> &'static [u32] {
    unsafe { core::slice::from_raw_parts(addr_of!(boot_page_directory) as *const u32, 1024) }
}

pub fn page_directory_mut() -> &'static mut [u32] {
    unsafe { core::slice::from_raw_parts_mut(addr_of_mut!(boot_page_directory) as *mut u32, 1024) }
}

pub fn init() {
    for (n, i) in page_directory().iter().enumerate() {
        if *i == 0 {
            continue;
        }

        qemu_log!("PD[{n}] = {i:#x}");
    }

    qemu_log!("Finished");
}