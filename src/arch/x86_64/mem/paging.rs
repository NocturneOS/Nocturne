use crate::{arch::get_page_size, mem::physical, qemu_log, tools};
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

const fn indices2vaddr(pml4: u64, pdpt: u64, pd: u64, pt: u64) -> u64 {
    (pml4 << 39) | (pdpt << 30) | (pd << 21) | (pt << 12)
}

const fn vaddr2indices(addr: usize) -> (usize, usize, usize, usize) {
    let addr = ((addr << 16) as isize >> 16) as usize;

    let pml4 = (addr >> 39) & 0x1FF;
    let pdpt = (addr >> 30) & 0x1FF;
    let pd = (addr >> 21) & 0x1FF;
    let pt = (addr >> 12) & 0x1FF;

    (pml4, pdpt, pd, pt)
}

// Recursive paging addresses.

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
pub fn pd(pml4t_idx: usize, pdpt_idx: usize) -> &'static [usize] {
    unsafe {
        core::slice::from_raw_parts(
            (PDT | (pml4t_idx << 21) | (pdpt_idx << 12)) as *const usize,
            512,
        )
    }
}

#[inline]
pub fn pd_mut(pml4t_idx: usize, pdpt_idx: usize) -> &'static mut [usize] {
    unsafe {
        core::slice::from_raw_parts_mut(
            (PDT | (pml4t_idx << 21) | (pdpt_idx << 12)) as *mut usize,
            512,
        )
    }
}

#[inline]
pub fn pt(pml4t_idx: usize, pdpt_idx: usize, pd_idx: usize) -> &'static [usize] {
    unsafe {
        core::slice::from_raw_parts(
            (PT | (pml4t_idx << 30) | (pdpt_idx << 21) | (pd_idx << 12)) as *const usize,
            512,
        )
    }
}

#[inline]
pub fn pt_mut(pml4t_idx: usize, pdpt_idx: usize, pd_idx: usize) -> &'static mut [usize] {
    unsafe {
        core::slice::from_raw_parts_mut(
            (PT | (pml4t_idx << 30) | (pdpt_idx << 21) | (pd_idx << 12)) as *mut usize,
            512,
        )
    }
}

pub fn map_single_page(physical_address: usize, virtual_address: usize, flags: PageFlags) {
    debug_assert!(physical_address % PAGE_SIZE == 0, "Physical address not page-aligned");
    debug_assert!(virtual_address % PAGE_SIZE == 0, "Virtual address not page-aligned");

    let (i_pml4t, i_pdpt, i_pdt, i_pt) = vaddr2indices(virtual_address);
    let v_pdpt = pml4t()[i_pml4t];

    let table_flags = PageFlags::Present | PageFlags::Writeable | 
                  (flags & PageFlags::Userspace);

    if v_pdpt == 0 {
        let new_pdpt = physical::allocate_one().unwrap();

        pml4t_mut()[i_pml4t] = new_pdpt | table_flags.bits();

        let pdpt_ = pdpt_mut(i_pml4t);
        pdpt_.fill(0);
    }

    let v_pdt = pdpt(i_pml4t)[i_pdpt];

    if v_pdt == 0 {
        let new_pdt = physical::allocate_one().unwrap();

        pdpt_mut(i_pml4t)[i_pdpt] = new_pdt | table_flags.bits();

        let pdt_ = pd_mut(i_pml4t, i_pdpt);
        pdt_.fill(0);
    }

    let v_pd = pd(i_pml4t, i_pdpt)[i_pdt];

    if v_pd == 0 {
        let new_pd = physical::allocate_one().unwrap();

        pd_mut(i_pml4t, i_pdpt)[i_pdt] = new_pd | table_flags.bits();

        let pt_ = pt_mut(i_pml4t, i_pdpt, i_pdt);
        pt_.fill(0);
    }

    let page_table = pt_mut(i_pml4t, i_pdpt, i_pdt);

    page_table[i_pt] = physical_address | flags.bits() | 1;

    unsafe { x86::tlb::flush(virtual_address) };

    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

pub fn unmap_single_page(virtual_address: usize) {
    let (i_pml4t, i_pdpt, i_pdt, i_pt) = vaddr2indices(virtual_address);
    let v_pdpt = pml4t()[i_pml4t];

    if v_pdpt == 0 {
        return;
    }

    let v_pdt = pdpt(i_pml4t)[i_pdpt];

    if v_pdt == 0 {
        return;
    }

    let v_pd = pd(i_pml4t, i_pdpt)[i_pdt];

    if v_pd == 0 {
        return;
    }

    let page_table = pt_mut(i_pml4t, i_pdpt, i_pdt);

    page_table[i_pt] = 0;

    unsafe { x86::tlb::flush(virtual_address) };
    
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
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
    let (pml4t_i, pdpt_i, pd_i, pt_i) = vaddr2indices(virt_addr & !0xfff);

    if (pml4t()[pml4t_i] & 1) == 0 {
        return None;
    }

    if (pml4t()[pml4t_i] & (1 << 7)) != 0 {
        let page_base = pml4t()[pml4t_i] & !0x3fff_ffff;

        return Some(page_base | (virt_addr & 0x3fff_ffff));
    }

    //

    if (pdpt(pml4t_i)[pdpt_i] & 1) == 0 {
        return None;
    }

    if (pdpt(pml4t_i)[pdpt_i] & (1 << 7)) != 0 {
        let page_base = pdpt(pml4t_i)[pdpt_i] & !0x1f_ffff;

        return Some(page_base | (virt_addr & 0x1f_ffff));
    }

    //

    if (pd(pml4t_i, pdpt_i)[pd_i] & 1) == 0 {
        return None;
    }

    if (pd(pml4t_i, pdpt_i)[pd_i] & (1 << 7)) != 0 {
        return Some(pd(pml4t_i, pdpt_i)[pd_i] & !0xfff);
    }

    //

    if (pt(pml4t_i, pdpt_i, pd_i)[pt_i] & 1) == 0 {
        return None;
    }

    Some(pt(pml4t_i, pdpt_i, pd_i)[pt_i] & !0xfff)
}

#[inline]
pub fn is_memory_accessible(addr: usize) -> bool {
    virt2phys(addr).is_some()
}


pub fn preinit(available_memory_size: usize) {
    let kernel_start = crate::sys::info::info_mut().kernel_start;
    let kernel_end = crate::sys::info::info_mut().kernel_end;

    let kernel_size = kernel_end - kernel_start;

    qemu_log!("Kernel: <{:016x} - {:016x}>", kernel_start, kernel_end);
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
