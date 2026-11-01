pub mod interrupts;
pub mod mem;
pub mod sys;
pub mod timer;

use core::alloc::Layout;

use crate::{arch, kmain, qemu_log};

use noct_mem::paging::PageFlags;
use noct_spec::units::Size;
use noct_video::{color_layout::ColorLayout, video_mode::VideoMode};

use multiboot2::{BootInformation, BootInformationHeader};

#[cfg(target_arch = "x86")]
#[unsafe(no_mangle)]
pub extern "C" fn __arch_init(multiboot_header: *const BootInformationHeader) -> ! {
    use noct_cpu::{gdt, idt, tss};

    qemu_log!("Welcome to NocturneOS NK {}!", env!("CARGO_PKG_VERSION"));
    
    let bootinfo = unsafe { BootInformation::load(multiboot_header).unwrap() };

    qemu_log!("Header area: {:#x?} - {:#x?}", bootinfo.start_address(), bootinfo.end_address());

    qemu_log!("Bootloader: {:?}", bootinfo.boot_loader_name_tag().unwrap().name());

    qemu_log!("Command line: {:?}", bootinfo.command_line_tag().and_then(|x| x.cmdline().ok()));
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

    // {
    //     let num = mb.num;
    //     let size = mb.size;
    //     let addr = mb.addr;
    //     let shndx = mb.shndx;

    //     qemu_log!("NUM: {:08x}", num);
    //     qemu_log!("SIZE: {:08x}", size);
    //     qemu_log!("ADDR: {:08x}", addr);
    //     qemu_log!("SHNDX: {:08x}", shndx);
    // }

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

    mem::paging::preinit(total_memory_size, &bootinfo);

    noct_physmem_alloc::init(&bootinfo);

    tss::init();

    // After physical memory initialization we have to mark reserved memory as used.
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

        qemu_log!("[reserved memmap] Marked {:#x?} - {:#x?} as reserved.", addr_start, addr_end);
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

    if let Some(mo) = bootinfo.module_tags().last() {
        let module_end_addr = (mo.end_address() as usize).next_multiple_of(arch::get_page_size());

        for addr in (0..module_end_addr).step_by(arch::get_page_size()) {
            noct_physmem_alloc::mark_page(addr, true);
        }

        qemu_log!(
            "[module] Marked area ({:08x} - {:08x}) as reserved.",
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

        info.installed_memory = Some(total_memory_size);

        // Set the start of `free memory zone` to the end of last module.
        // If no modules specified, use kernel end address.
        info.available_memory_start = Some(available_memory_start);
    }

    noct_cpu::pat::write_pat();

    timer::pit::init(1000);

    unsafe { x86::irq::enable() };

    kmain(bootinfo);
}

pub fn post_init(boot: &BootInformation) {
    qemu_log!("Post init...");

    // Init RTC
    noct_rtc::init();

    // Init video
    let fb = boot.framebuffer_tag().unwrap().unwrap();

    let phys_addr = fb.address();

    let size = (fb.width() * fb.height() * (fb.bpp() as u32 >> 3)) as usize;

    qemu_log!("Framebuffer @ {:#x?} ({}x{}@{})", phys_addr, fb.width(), fb.height(), fb.bpp());

    let ptr = unsafe { noct_mem::heap::allocate_no_map(Layout::from_size_align_unchecked(size, 0x1000)) };

    // PAT = Write-Combining
    let flags = PageFlags::empty().with_pat(0b100) | PageFlags::Writeable;

    noct_mem::paging::map_pages(phys_addr as _, ptr.addr(), size as _, flags);

    let mut lock = noct_video::CURRENT_VIDEO_MODE.lock();

    *lock = Some(VideoMode::new_graphics(
        ptr,
        phys_addr as _,
        Size::from((
            fb.width() as _,
            fb.height() as _,
        )),
        (fb.bpp() >> 3) as _,
        ColorLayout::new(16, 8, 0)
    ));

    qemu_log!("Video initialized");


    // Now, initialize ACPI

    if let Err(e) = noct_acpi::init() {
        panic!("ACPI initialization failed! ({e:?})");
    };
}
