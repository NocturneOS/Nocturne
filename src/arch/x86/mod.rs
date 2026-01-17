pub mod gdt;
pub mod idt;
pub mod interrupts;
pub mod mem;
pub mod multiboot;
pub mod timer;
pub mod video;

#[repr(C, packed(1))]
#[derive(Debug)]
pub struct CPURegisters {
    pub ds: u32,
    pub edi: u32,
    pub esi: u32,
    pub ebp: u32,
    pub esp: u32,
    pub ebx: u32,
    pub edx: u32,
    pub ecx: u32,
    pub eax: u32,
    pub int_num: u32,
    pub err_code: u32,
    pub eip: u32,
    pub cs: u32,
    pub eflags: u32,
    pub useresp: u32,
    pub ss: u32
}

use crate::{arch::x86::multiboot::MultibootHeader, kmain, qemu_log};

#[unsafe(no_mangle)]
pub extern "C" fn __arch_init(multiboot_header_address: usize) -> ! {
    qemu_log!("Welcome to NocturneOS NK {}!", env!("CARGO_PKG_VERSION"));

    let mb = unsafe { &*((multiboot_header_address + 0xC000_0000) as *const MultibootHeader) };

    qemu_log!("Command line: {:?}", mb.cmdline());
    qemu_log!("Modules count: {}", mb.modules().len());

    for i in mb.modules() {
        qemu_log!("- {:?} <{:08x} - {:08x}>", i.cmdline(), i.start(), i.end());
    }

    qemu_log!("Memory: {} KB (lower) / {} KB (upper)", mb.memory().0, mb.memory().1);

    for i in mb.mmap() {
        qemu_log!("- {:?} <{:08x} - {:08x}>", i.ty(), i.addr(), i.addr() + i.length());
    }

    gdt::init();
    idt::init();

    interrupts::exceptions::register_exceptions();
    interrupts::pic::init();

    mem::paging::init();

    timer::pit::init(1000);
    
    unsafe { x86::irq::enable() };
    
    kmain()
}