use multiboot2::{BootInformation, BootInformationHeader};
use noct_cpu::{gdt, idt, tss};
use noct_mem::paging;
use noct_multiboot::{MultibootHeader, MultibootMMapType};

use crate::arch::x86::{interrupts, sys, timer};
use crate::{arch, kmain, qemu_log};

use noct_boot::{BootInfo, Module};

#[unsafe(no_mangle)]
pub extern "C" fn __arch_init(header: *const BootInformationHeader) -> ! {
    qemu_log!("Welcome to NocturneOS NK {}!", env!("CARGO_PKG_VERSION"));

    let bootinfo = unsafe { BootInformation::load(header).unwrap() };

    qemu_log!(
        "Header area: {:#x?} - {:#x?}",
        bootinfo.start_address(),
        bootinfo.end_address()
    );

    qemu_log!(
        "Bootloader: {:?}",
        bootinfo.boot_loader_name_tag().unwrap().name()
    );

    qemu_log!("Command line: {:?}", bootinfo.command_line_tag());
    qemu_log!("Modules count: {:?}", bootinfo.module_tags().count());

    for i in bootinfo.module_tags() {
        qemu_log!(
            "- {:?} <{:#x?} - {:#x?}>",
            i.cmdline().unwrap(),
            i.start_address() as *const usize,
            i.end_address() as *const usize
        );
    }

    qemu_log!(
        "Memory: {} KB (lower) / {} KB (upper)",
        bootinfo.basic_memory_info_tag().unwrap().memory_lower(),
        bootinfo.basic_memory_info_tag().unwrap().memory_upper()
    );

    for i in bootinfo.memory_map_tag().unwrap().memory_areas() {
        qemu_log!(
            "- {:?} <{:08x} - {:08x}>",
            i.typ(),
            i.start_address(),
            i.end_address()
        );
    }

    // Fill system info

    sys::init(&bootinfo);

    gdt::init();
    idt::init();

    interrupts::exceptions::register_exceptions();
    interrupts::pic::init();

    let total_memory_size = (bootinfo
        .basic_memory_info_tag()
        .map(|x| x.memory_lower() + x.memory_upper())
        .unwrap()
        << 10) as _;

    paging::preinit(total_memory_size);

    noct_physmem_alloc::init(&bootinfo);

    tss::init();

    for i in bootinfo
        .memory_map_tag()
        .unwrap()
        .memory_areas()
        .iter()
        .filter(|x| x.typ() != multiboot2::MemoryAreaType::Available)
        .map(|x| (x.start_address(), x.size()))
    {
        let addr_start = noct_tools::align_value(i.0.try_into().unwrap(), arch::get_page_size());

        if i.0 + i.1 - 1 >= usize::MAX as _ {
            break;
        }

        let addr_end =
            noct_tools::align_value((i.0 + i.1 - 1).try_into().unwrap(), arch::get_page_size());

        if addr_start > total_memory_size {
            continue;
        }

        for addr in (addr_start..addr_end).step_by(arch::get_page_size()) {
            noct_physmem_alloc::mark_page(addr.try_into().unwrap(), true);
        }

        qemu_log!("Marked {:#x?} - {:#x?} as reserved.", addr_start, addr_end);
    }

    // Mark all the memory past the kernel (and the kernel region) as used

    {
        let start = (noct_sysinfo::info().kernel_end - noct_spec::KERNEL_BASE) + paging::PAGE_SIZE;

        for addr in (0..start).step_by(arch::get_page_size()) {
            noct_physmem_alloc::mark_page(addr, true);
        }

        qemu_log!(
            "Marked {:#x?} - {:#x?} as used. (past the kernel)",
            0,
            start
        );
    }

    // Reserve memory for modules we load.

    {
        let kernel_area = noct_sysinfo::info().kernel_area_end - noct_spec::KERNEL_BASE;

        for addr in (0..kernel_area).step_by(arch::get_page_size()) {
            noct_physmem_alloc::mark_page(addr, true);
        }

        qemu_log!(
            "[kernel area] Marked area {:08x} - {:08x} as reserved.",
            0,
            kernel_area
        );
    }

    {
        if let Some(mo) = bootinfo.module_tags().last() {
            let module_end_addr =
                (mo.end_address() as usize).next_multiple_of(arch::get_page_size());

            for addr in (0..module_end_addr).step_by(arch::get_page_size()) {
                noct_physmem_alloc::mark_page(addr, true);
            }

            qemu_log!(
                "[module] Marked area ({:08x} - {:08x}) as reserved.",
                0,
                module_end_addr
            );
        }
    }

    // Update info for `kmain`
    {
        let bitmap_end = noct_physmem_alloc::get_bitmap_range();
        let available_memory_start = bitmap_end.end.next_multiple_of(arch::get_page_size());

        let mut info = noct_sysinfo::info_mut();

        info.installed_memory = Some(total_memory_size);

        // Set the start of `free memory zone` to the end of last module.
        // If no modules specified, use kernel end address.
        info.available_memory_start = Some(available_memory_start);
        /* Some(
            mb.modules()
                .last()
                .map(|x| x.mod_end as usize)
                .unwrap_or(kernel_end - noct_spec::KERNEL_BASE),
        );*/
    }

    noct_cpu::pat::write_pat();

    timer::pit::init(1000);

    unsafe { x86::irq::enable() };

    kmain(bootinfo);
}

// After memory is initialized, some hardware will require additional setup.
pub fn post_init(boot: &BootInformation) {
    // qemu_log!("Post init...");

    crate::arch::x86::post_init(boot);
}
