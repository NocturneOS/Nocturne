pub mod mem;
pub mod regs;

use crate::spec::KERNEL_BASE;
use crate::arch::x86::multiboot::MultibootHeader;
use crate::arch::x86::sys;
use crate::qemu_log;

#[unsafe(no_mangle)]
pub extern "C" fn __arch_init(multiboot_header_address: usize) -> ! {
    qemu_log!("Welcome to NocturneOS NK {}!", env!("CARGO_PKG_VERSION"));

    let mb = unsafe { &*((multiboot_header_address + KERNEL_BASE) as *const MultibootHeader) };

    qemu_log!("Command line: {:?}", mb.cmdline());
    qemu_log!("Modules count: {}", mb.modules().len());

    for i in mb.modules() {
        qemu_log!("- {:?} <{:08x} - {:08x}>", i.cmdline(), i.start(), i.end());
    }

    qemu_log!(
        "Memory: {} KB (lower) / {} KB (upper)",
        mb.memory().low() >> 10,
        mb.memory().high() >> 10
    );

    for i in mb.mmap() {
        qemu_log!(
            "- {:?} <{:08x} - {:08x}>",
            i.ty(),
            i.addr(),
            i.addr() + i.length()
        );
    }

    {
        let num = mb.num;
        let size = mb.size;
        let addr = mb.addr;
        let shndx = mb.shndx;

        qemu_log!("NUM: {:08x}", num);
        qemu_log!("SIZE: {:08x}", size);
        qemu_log!("ADDR: {:08x}", addr);
        qemu_log!("SHNDX: {:08x}", shndx);
    }

    // Fill system info
    
    sys::init();


    loop {}
}
