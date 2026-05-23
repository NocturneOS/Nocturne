use noct_mem::paging;
use noct_spec::WORD_SIZE;

use crate::qemu_log;

// Kernel memory layout:
// C000_0000: BIOS zone
// C010_0000: Kernel itself
// C010_0000 + KERNEL_SIZE: Physical memory bitmap

pub fn preinit(available_memory_size: usize) {
    let kernel_start = noct_sysinfo::info_mut().kernel_start;
    let kernel_end = noct_sysinfo::info_mut().kernel_end;

    let kernel_size = kernel_end - kernel_start;

    qemu_log!("Kernel: <{:08x} - {:08x}>", kernel_start, kernel_end);
    qemu_log!("Kernel size is: {kernel_size:x}");

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
    let total_needed_size = kernel_size + phys_bitmap_size;

    qemu_log!("Total size: {} bytes", total_needed_size);

    let total_needed_pages = total_needed_size / paging::PAGE_SIZE;

    qemu_log!("Total page count: {}", total_needed_pages);

    if total_needed_pages > 1024 {
        // I would allocate a second page table or even recreate a page directory from scratch,
        // but in this stage we can't have an allocator.

        // TODO: Use extended 4MB pages instead? They don't have to allocate.
        panic!(
            "Needed more than one page table for kernel initialization! (Total pages needed: {})",
            total_needed_pages
        );
    }

    // We did all checks, let's list the entries.

    for (n, i) in noct_mem::paging::page_directory().iter().enumerate() {
        if *i == 0 {
            continue;
        }

        qemu_log!("PD[{n}] = {:#x}", i.raw());
    }

    qemu_log!("Finished");
}