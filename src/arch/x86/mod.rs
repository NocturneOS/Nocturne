pub mod dev;
pub mod interrupts;
pub mod io;
pub mod mem;
pub mod sys;
pub mod timer;
pub mod video;

use crate::{
    arch::{self},
    kmain, qemu_log,
};

use noct_multiboot::MultibootHeader;

#[cfg(target_arch = "x86")]
#[unsafe(no_mangle)]
pub extern "C" fn __arch_init(multiboot_header_address: usize) -> ! {
    use noct_boot::BootInfo;
    use noct_cpu::{gdt, idt, tss};
    use noct_multiboot::MultibootMMapType;

    qemu_log!("Welcome to NocturneOS NK {}!", env!("CARGO_PKG_VERSION"));

    let mb = unsafe {
        use noct_spec::KERNEL_BASE;
        &*((multiboot_header_address + KERNEL_BASE) as *const MultibootHeader)
    };

    qemu_log!("Command line: {:?}", mb.cmdline());
    qemu_log!("Modules count: {}", mb.modules().count());

    for i in mb.modules() {
        use noct_boot::Module;

        qemu_log!(
            "- {:?} <{:#x?} - {:#x?}>",
            i.cmdline().unwrap(),
            i.start() as *const usize,
            i.end() as *const usize
        );
    }

    qemu_log!(
        "Memory: {} KB (lower) / {} KB (upper)",
        mb.memory().lower() >> 10,
        mb.memory().higher() >> 10
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

    sys::init(mb);

    gdt::init();
    idt::init();

    interrupts::exceptions::register_exceptions();
    interrupts::pic::init();

    mem::paging::preinit(mb.memory().total(), mb);

    noct_physmem_alloc::init(mb);

    tss::init();

    // After physical memory initialization we have to mark reserved memory as used.
    for i in mb
        .mmap()
        .iter()
        .filter(|x| x.ty() != MultibootMMapType::Available)
        .map(|x| (x.addr(), x.length()))
    {
        let addr_start = noct_tools::align_value(i.0.try_into().unwrap(), arch::get_page_size());

        if i.0 + i.1 - 1 >= usize::MAX as _ {
            break;
        }

        let addr_end =
            noct_tools::align_value((i.0 + i.1 - 1).try_into().unwrap(), arch::get_page_size());

        if addr_start > mb.memory().total() {
            continue;
        }

        for addr in (addr_start..addr_end).step_by(arch::get_page_size()) {
            noct_physmem_alloc::mark_page(addr.try_into().unwrap(), true);
        }

        qemu_log!("Marked {:#x?} - {:#x?} as reserved.", addr_start, addr_end);
    }

    // Reserve memory for modules we load.

    if let Some(mo) = mb.modules().last() {
        use noct_boot::Module;

        let module_end_addr = mo.end().next_multiple_of(arch::get_page_size());

        for addr in (0..module_end_addr).step_by(arch::get_page_size()) {
            noct_physmem_alloc::mark_page(addr, true);
        }

        qemu_log!(
            "Marked area ({:08x} - {:08x}) as reserved.",
            0,
            module_end_addr
        );
    }

    // Update info for `kmain`
    {
        let bitmap_end = noct_physmem_alloc::get_bitmap_range();
        let available_memory_start = bitmap_end.end.next_multiple_of(arch::get_page_size());

        qemu_log!("Range: {bitmap_end:x?}");
        qemu_log!("Memory start: {available_memory_start:x?}");

        let mut info = noct_sysinfo::info_mut();

        info.installed_memory = Some(mb.memory().total());

        // Set the start of `free memory zone` to the end of last module.
        // If no modules specified, use kernel end address.
        info.available_memory_start = Some(available_memory_start);
    }

    timer::pit::init(1000);

    unsafe { x86::irq::enable() };

    kmain(mb)
}
