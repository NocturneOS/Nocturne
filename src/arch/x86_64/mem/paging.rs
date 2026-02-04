use crate::{arch::get_page_size, qemu_log, tools};
use bitflags::bitflags;
use cfg_if::cfg_if;

pub const PAGE_SIZE: usize = 0x1000;

bitflags! {
    #[derive(Copy, Clone)]
    pub struct PageFlags : usize {
        const Present = 1 << 0;
        const Writeable = 1 << 1;
        const Userspace = 1 << 2;
        const WriteThrough = 1 << 3;
        const CacheDisable = 1 << 4;
        const Accessed = 1 << 5;
        const Dirty = 1 << 6;
        const Extended = 1 << 7;
        const Global = 1 << 8;
    }
}

unsafe extern "C" {
    // Defined in src/arch/x86/asm/init.s
    static mut boot_page_directory: [u32; 1024];

}

const fn indices_to_addr(pml4: u64, pdpt: u64, pd: u64, pt: u64) -> u64 {
    (pml4 << 39) | (pdpt << 30) | (pd << 21) | (pt << 12)
}

const fn addr_to_indices(addr: u64) -> (u64, u64, u64, u64) {
    let pml4 = (addr >> 39) & 0x1FF;
    let pdpt = (addr >> 30) & 0x1FF;
    let pd = (addr >> 21) & 0x1FF;
    let pt = (addr >> 12) & 0x1FF;

    (pml4, pdpt, pd, pt)
}

const PML4T: usize = 0xFFFF_FF7F_BFDF_E000;  // (510, 510, 510, 510)
const PDPT: usize = 0xFFFF_FF7F_BFC0_0000;   // (510, 510, 510, 0)
const PDT: usize = 0xFFFF_FF7F_8000_0000;    // (510, 510, 0, 0)
const PT: usize = 0xFFFF_FF00_0000_0000;     // (510, 0, 0, 0)

#[inline]
pub fn pml4t() -> &'static [usize] {
    unsafe { core::slice::from_raw_parts(PML4T as *const usize, 512) }
}

#[inline]
pub fn pml4t_mut() -> &'static mut [usize] {
    unsafe { core::slice::from_raw_parts_mut(PML4T as *mut usize, 512) }
}

#[inline]
pub fn pdpt(pml4t_idx: usize) -> &'static [usize] {
    unsafe { core::slice::from_raw_parts((PDPT | (pml4t_idx << 12)) as *const usize, 512) }
}

#[inline]
pub fn pdpt_mut(pml4t_idx: usize) -> &'static mut [usize] {
    unsafe { core::slice::from_raw_parts_mut((PDPT | (pml4t_idx << 12)) as *mut usize, 512) }
}

#[inline]
pub fn pd(pml4t_idx: usize, pd_idx: usize) -> &'static [usize] {
    unsafe {
        core::slice::from_raw_parts(
            (PDT | (pml4t_idx << 21) | (pd_idx << 12)) as *const usize,
            512,
        )
    }
}

#[inline]
pub fn pd_mut(pml4t_idx: usize, pd_idx: usize) -> &'static mut [usize] {
    unsafe {
        core::slice::from_raw_parts_mut(
            (PDT | (pml4t_idx << 21) | (pd_idx << 12)) as *mut usize,
            512,
        )
    }
}

#[inline]
pub fn pt(pml4t_idx: usize, pd_idx: usize, pt_idx: usize) -> &'static [usize] {
    unsafe {
        core::slice::from_raw_parts(
            (PT | (pml4t_idx << 30) | (pd_idx << 21) | (pt_idx << 12)) as *const usize,
            512,
        )
    }
}

#[inline]
pub fn pt_mut(pml4t_idx: usize, pd_idx: usize, pt_idx: usize) -> &'static mut [usize] {
    unsafe {
        core::slice::from_raw_parts_mut(
            (PT | (pml4t_idx << 30) | (pd_idx << 21) | (pt_idx << 12)) as *mut usize,
            512,
        )
    }
}

pub fn map_single_page(physical_address: usize, virtual_address: usize, flags: PageFlags) {
    todo!()
}

pub fn unmap_single_page(virtual_address: usize) {
    todo!()
}

pub fn map_pages(phys_addr: usize, virt_addr: usize, byte_count: usize, flags: PageFlags) {
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
    todo!()
}

#[inline]
pub fn is_memory_accessible(addr: usize) -> bool {
    virt2phys(addr).is_some()
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

    if total_needed_pages > 512 {
        // I would allocate a second page table or even recreate a page directory from scratch,
        // but in this stage we can't have an allocator.

        // TODO: Use extended pages instead? They don't have to allocate.
        panic!(
            "Needed more than one page table for kernel initialization! (Total pages needed: {})",
            total_needed_pages
        );
    }

    // We did all checks, let's list the entries.

    for (n, i) in pml4t().iter().enumerate() {
        if *i == 0 || n == 510 {
            continue;
        }

        qemu_log!("PML4T[{n}] = {i:#x}");

        for (n2, i2) in pdpt(n).iter().enumerate() {
            if *i2 == 0 {
                continue;
            }

            qemu_log!("  PDPT[{n2}] = {i2:#x}");

            for (n3, i3) in pd(n, n2).iter().enumerate() {
                if *i3 == 0 {
                    continue;
                }

                qemu_log!("    PD[{n3}] = {i3:#x}");
            }
        }
    }

    qemu_log!("Finished");
}
