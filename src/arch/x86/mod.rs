pub mod gdt;
pub mod idt;
pub mod timer;
pub mod video;

#[repr(C, packed(1))]
pub struct CPURegisters {
    ds: u32,
    edi: u32,
    esi: u32,
    ebp: u32,
    esp: u32,
    ebx: u32,
    edx: u32,
    ecx: u32,
    eax: u32,
    int_num: u32,
    err_code: u32,
    eip: u32,
    cs: u32,
    eflags: u32,
    useresp: u32,
    ss: u32
}

use crate::kmain;

#[unsafe(no_mangle)]
pub extern "C" fn __arch_init(data: usize) -> ! {
    gdt::init();
    idt::init();

    kmain()
}