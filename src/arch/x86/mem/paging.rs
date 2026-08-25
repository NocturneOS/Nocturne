use noct_boot::Module;
use noct_mem::paging::{self, GlobalPagingArchitecture, Page, PageFlags, PagingHierarchy};
use noct_spec::WORD_SIZE;

use multiboot2::BootInformation;

use crate::qemu_log;

// Kernel memory layout:
// C000_0000: BIOS zone
// C010_0000: Kernel itself
// C010_0000 + KERNEL_SIZE: Physical memory bitmap

pub fn preinit(
    available_memory_size: usize,
    boot: &BootInformation,
) {
    let kernel_start = noct_sysinfo::info().kernel_start;
    let kernel_end = noct_sysinfo::info().kernel_end;
    let kernel_area_end = noct_sysinfo::info().kernel_area_end;

    let kernel_size = kernel_end - kernel_start;
    let complete_kernel_size = kernel_area_end - kernel_start;

    qemu_log!("Kernel: <{:08x} - {:08x}>", kernel_start, kernel_end);
    qemu_log!("Kernel with modules: <{:08x} - {:08x}>", kernel_start, kernel_area_end);

    qemu_log!("Kernel size is: {kernel_size:x}");
    qemu_log!("Complete kernel size is: {complete_kernel_size:x}");

    qemu_log!("Available memory: {:#?}", available_memory_size);
    qemu_log!("Pages: {:?}", available_memory_size / paging::PAGE_SIZE);

    // Divide memory by pages and then by 8 (bits in one byte) - it's the bitmap size.
    let mut phys_bitmap_size = (available_memory_size / paging::PAGE_SIZE) / 8;

    // Align it to usize boundary.
    if !phys_bitmap_size.is_multiple_of(WORD_SIZE) {
        qemu_log!("Aligning it");
        phys_bitmap_size = noct_tools::align_value(phys_bitmap_size, WORD_SIZE);
    }

    noct_sysinfo::info_mut().physical_memory_bitmap_size = Some(phys_bitmap_size);

    qemu_log!("Physical memory bitmap size: {} bytes", phys_bitmap_size);

    // Combine it together
    let total_needed_size = complete_kernel_size + phys_bitmap_size;

    let real_kernel_end = kernel_start + total_needed_size;

    qemu_log!("Kernel with modules and bitmap: <{:08x} - {:08x}>", kernel_start, real_kernel_end);

    // KERNEL_BASE is chosen because it's always 0xC000_0000 which is 0x400_000-aligned.
    for addr in (noct_spec::KERNEL_BASE..real_kernel_end).step_by(0x400_000) {
        let idx = GlobalPagingArchitecture::index_at_level(addr, 0);
        let pt = noct_mem::paging::page_directory_mut().get_mut(idx).unwrap();

        qemu_log!("Extended page: {:08x} (present: {})", addr, pt.is_present());

        // If page is not present, map it.
        if !pt.is_present() {
            let phys = addr - noct_spec::KERNEL_BASE;

            *pt = Page::new(phys, PageFlags::Present | PageFlags::Writeable | PageFlags::Extended);
        }
    }

    qemu_log!("Total size: {} bytes", total_needed_size);

    // We did all checks, let's list the entries.

    for (n, i) in noct_mem::paging::page_directory().iter().enumerate() {
        if *i == 0 {
            continue;
        }

        qemu_log!("PD[{n}] = {:#x}", i.raw());
    }

    qemu_log!("Finished");
}
