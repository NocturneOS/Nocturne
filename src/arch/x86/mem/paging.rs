use crate::{arch::get_page_size, qemu_log, tools};

pub const PAGE_SIZE: usize = 0x1000;

unsafe extern "C" {
    // Defined in src/arch/x86/asm/init.s
    static mut boot_page_directory: [u32; 1024];

}

pub fn page_directory() -> &'static [usize] {
    unsafe { core::slice::from_raw_parts(0xFFFF_F000 as *const usize, 1023) }
}

pub fn page_directory_mut() -> &'static mut [usize] {
    unsafe { core::slice::from_raw_parts_mut(0xFFFF_F000 as *mut usize, 1023) }
}

pub fn page_table(pd_idx: usize) -> &'static [usize] {
    unsafe {
        core::slice::from_raw_parts((0xFFC0_0000 + (pd_idx * PAGE_SIZE)) as *const usize, 1024)
    }
}

pub fn page_table_mut(pd_idx: usize) -> &'static mut [usize] {
    unsafe {
        core::slice::from_raw_parts_mut((0xFFC0_0000 + (pd_idx * PAGE_SIZE)) as *mut usize, 1024)
    }
}

pub fn vaddr2indices(vaddr: usize) -> (usize, usize) {
    (vaddr >> 22, (vaddr >> 12) & 0x3ff)
}

pub fn map_single_page(physical_address: usize, virtual_address: usize, flags: u32) {
    let (pdi, pti) = vaddr2indices(virtual_address);
    let pt = page_directory()[pdi];

    if pt == 0 {
        let new_pt = crate::mem::physical::allocate_one().unwrap();

        page_directory_mut()[pdi] = new_pt | 3;

        let page_table = page_table_mut(pdi);
        page_table.fill(0);
    }

    let page_table = page_table_mut(pdi);

    page_table[pti] = physical_address | flags as usize | 1;

    unsafe { x86::tlb::flush(virtual_address) };
}

pub fn unmap_single_page(virtual_address: usize) {
    let (pdi, pti) = vaddr2indices(virtual_address);

    let pt = page_directory()[pdi];

    if pt == 0 {
        return;
    }

    let page_table = page_table_mut(pdi);

    page_table[pti] = 0;

    unsafe { x86::tlb::flush(virtual_address) };
}

pub fn map_pages(phys_addr: usize, virt_addr: usize, byte_count: usize, flags: u32) {
    let page_size = get_page_size();
    let pages_count = byte_count.div_ceil(page_size);

    for n in 0..pages_count {
        map_single_page(
            phys_addr + (n * page_size),
            virt_addr + (n * page_size),
            flags,
        );
    }
}

pub fn unmap_pages(virt_addr: usize, byte_count: usize) {
    let page_size = get_page_size();
    let pages_count = byte_count.div_ceil(page_size);

    for n in 0..pages_count {
        unmap_single_page(virt_addr + (n * page_size));
    }
}

pub fn virt2phys(virt_addr: usize) -> Option<usize> {
    let (pdi, pti) = vaddr2indices(virt_addr & !0xfff);

    // If no page table in page directory, exit.
    if (page_directory()[pdi] & 1) == 0 {
        return None;
    }

    // If page directory entry is an extended page, return it.
    if (page_directory()[pdi] & (1 << 7)) != 0 {
        return Some(page_directory()[pdi] & !0xfff);
    }

    // Otherwise, get the page table entry and clear service bits.
    Some(page_table(pdi)[pti] & !0x3ff)
}

// Kernel memory layout:
// C000_0000: BIOS zone
// C010_0000: Kernel itself
// C010_0000 + KERNEL_SIZE: Physical memory bitmap

pub fn preinit(available_memory_size: usize) {
    let kernel_start = crate::sys::info::info_mut().kernel_start;
    let kernel_end = crate::sys::info::info_mut().kernel_end;

    let kernel_size = kernel_end - kernel_start;

    qemu_log!("Kernel: <{:08x} - {:08x}>", kernel_start, kernel_end);
    qemu_log!("Kernel size is: {kernel_size:x}");

    qemu_log!("Available memory: {:#?}", available_memory_size);
    qemu_log!("Pages: {:?}", available_memory_size / PAGE_SIZE);

    // Divide memory by pages and then by 8 (bits in one byte) - it's the bitmap size.
    let mut phys_bitmap_size = (available_memory_size / PAGE_SIZE) / 8;

    // Align it to usize boundary.
    if !phys_bitmap_size.is_multiple_of(crate::spec::WORD_SIZE) {
        qemu_log!("Aligning it");
        phys_bitmap_size = tools::align_value(phys_bitmap_size, crate::spec::WORD_SIZE);
    }

    crate::sys::info::info_mut().physical_memory_bitmap_size = Some(phys_bitmap_size);

    qemu_log!("Physical memory bitmap size: {} bytes", phys_bitmap_size);

    // Combine it together
    let total_needed_size = kernel_size + phys_bitmap_size;

    qemu_log!("Total size: {} bytes", total_needed_size);

    let total_needed_pages = total_needed_size / PAGE_SIZE;

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

    for (n, i) in page_directory().iter().enumerate() {
        if *i == 0 {
            continue;
        }

        qemu_log!("PD[{n}] = {i:#x}");
    }

    qemu_log!("Finished");
}
