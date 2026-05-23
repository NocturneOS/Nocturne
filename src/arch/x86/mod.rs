pub mod dev;
pub mod interrupts;
pub mod io;
pub mod mem;
pub mod multiboot;
pub mod sys;
pub mod timer;
pub mod video;

use crate::{
    arch::{
        self,
        x86::multiboot::{MultibootHeader, MultibootMMapType},
    },
    kmain, qemu_log,
};

#[cfg(target_arch = "x86")]
#[unsafe(no_mangle)]
pub extern "C" fn __arch_init(multiboot_header_address: usize) -> ! {
    use noct_boot::BootInfo;
use noct_cpu::{gdt, idt, tss};

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

    sys::init();

    gdt::init();
    idt::init();

    interrupts::exceptions::register_exceptions();
    interrupts::pic::init();

    mem::paging::preinit(mb.memory().total());

    noct_physmem_alloc::init();

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

    // Mark all the memory past the kernel (and the kernel region) as used

    {
        use noct_spec::KERNEL_BASE;

        let start = (noct_sysinfo::info().kernel_end - KERNEL_BASE) + noct_mem::paging::PAGE_SIZE;

        for addr in (0..start).step_by(arch::get_page_size()) {
            noct_physmem_alloc::mark_page(addr, true);
        }

        qemu_log!("Marked {:#x?} - {:#x?} as used.", 0, start);
    }

    // Reserve memory for modules we load.

    {
        for (n, i) in mb.modules().enumerate() {
            use noct_boot::Module;

            let start_addr = i.mod_start as usize;
            let end_addr = noct_tools::align_value(i.mod_end as usize, arch::get_page_size());

            for addr in (start_addr..end_addr).step_by(arch::get_page_size()) {
                noct_physmem_alloc::mark_page(addr, true);
            }

            qemu_log!(
                "Marked module #{} {:#?} ({:x} - {:x}) as reserved.",
                n,
                i.cmdline(),
                start_addr,
                end_addr
            );
        }
    }

    // Update info for `kmain`
    {
        use noct_spec::KERNEL_BASE;

        let kernel_end = noct_sysinfo::info().kernel_end;
        let mut info = noct_sysinfo::info_mut();

        info.installed_memory = Some(mb.memory().total());

        // Set the start of `free memory zone` to the end of last module.
        // If no modules specified, use kernel end address.
        info.available_memory_start = Some(
            mb.modules()
                .last()
                .map(|x| x.mod_end as usize)
                .unwrap_or(kernel_end - KERNEL_BASE),
        );
    }

    timer::pit::init(1000);

    unsafe { x86::irq::enable() };

    kmain(mb)
}
