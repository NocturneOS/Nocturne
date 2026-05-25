use core::sync::atomic::Ordering;

use crate::paging::Page;
use crate::paging::PageFlags;
use crate::paging::PagingHierarchy;

pub struct X86Paging;

pub type GlobalPagingArchitecture = X86Paging;

impl PagingHierarchy for X86Paging {
    const LEVELS: usize = 2;
    const ENTRIES: usize = 1024;
    const RECURSIVE_INDEX: usize = 1023;

    fn index_at_level(vaddr: usize, level: usize) -> usize {
        match level {
            0 => vaddr >> 22,
            1 => (vaddr >> 12) & 0x3FF,
            _ => unreachable!(),
        }
    }

    // 0x0000_0000 - 0xC000_0000
    fn user_root_entry_count() -> usize {
        768
    }

    fn root() -> &'static [usize] {
        unsafe { core::slice::from_raw_parts(0xFFFF_F000 as *const usize, 1023) }
    }
}

pub const PAGE_SIZE: usize = 0x1000;

#[inline]
pub fn page_directory() -> &'static [Page] {
    unsafe { core::slice::from_raw_parts(0xFFFF_F000 as *const Page, 1023) }
}

#[inline]
pub fn page_directory_mut() -> &'static mut [Page] {
    unsafe { core::slice::from_raw_parts_mut(0xFFFF_F000 as *mut Page, 1023) }
}

#[inline]
pub fn page_table(pd_idx: usize) -> &'static [Page] {
    unsafe {
        core::slice::from_raw_parts((0xFFC0_0000 + (pd_idx * PAGE_SIZE)) as *const Page, 1024)
    }
}

#[inline]
pub fn page_table_mut(pd_idx: usize) -> &'static mut [Page] {
    unsafe {
        core::slice::from_raw_parts_mut((0xFFC0_0000 + (pd_idx * PAGE_SIZE)) as *mut Page, 1024)
    }
}

#[inline]
pub fn vaddr2indices(vaddr: usize) -> (usize, usize) {
    (vaddr >> 22, (vaddr >> 12) & 0x3ff)
}

#[inline]
pub fn indices2vaddr(pde: usize, pte: usize) -> usize {
    (pde << 22) | (pte << 12)
}

pub fn map_single_page(physical_address: usize, virtual_address: usize, flags: PageFlags) {
    let (pdi, pti) = vaddr2indices(virtual_address);
    let pt = page_directory()[pdi];

    let table_flags = PageFlags::Present | PageFlags::Writeable | (flags & PageFlags::Userspace);

    if pt == 0 {
        let new_pt = noct_physmem_alloc::allocate_one().unwrap();

        page_directory_mut()[pdi] = Page(new_pt | table_flags.bits());

        let page_table = page_table_mut(pdi);
        page_table.fill(Page::null());
    }

    let page_table = page_table_mut(pdi);

    page_table[pti] = Page(physical_address | (flags | PageFlags::Present).bits());

    unsafe { x86::tlb::flush(virtual_address) };

    core::sync::atomic::compiler_fence(Ordering::Acquire);
}

pub fn unmap_single_page(virtual_address: usize) {
    let (pdi, pti) = vaddr2indices(virtual_address);

    let pt = page_directory()[pdi];

    if pt == 0 {
        return;
    }

    let page_table = page_table_mut(pdi);

    page_table[pti] = Page::null();

    unsafe { x86::tlb::flush(virtual_address) };

    core::sync::atomic::compiler_fence(Ordering::Acquire);
}

pub fn map_pages(phys_addr: usize, virt_addr: usize, byte_count: usize, flags: PageFlags) {
    let page_size = PAGE_SIZE;
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
    let page_size = PAGE_SIZE;
    let pages_count = byte_count.div_ceil(page_size);

    for n in 0..pages_count {
        unmap_single_page(virt_addr + (n * page_size));
    }
}

pub fn virt2phys(virt_addr: usize) -> Option<usize> {
    let (pdi, pti) = vaddr2indices(virt_addr & !0xfff);

    // If no page table in page directory, exit.
    if !page_directory()[pdi].is_present() {
        return None;
    }

    // If page directory entry is an extended page, return it.
    if page_directory()[pdi].is_extended() {
        return Some(page_directory()[pdi].phys());
    }

    // If page is not mapped in page table, exit.
    if !page_table(pdi)[pti].is_present() {
        return None;
    }

    // Otherwise, get the page table entry and clear service bits.
    Some(page_table(pdi)[pti].0 & !0x3ff)
}

pub fn virt2phys_precise(virt_addr: usize) -> Option<usize> {
    let (pdi, pti) = vaddr2indices(virt_addr & !0xfff);

    // If no page table in page directory, exit.
    if !page_directory()[pdi].is_present() {
        return None;
    }

    // If page directory entry is an extended page, return it.
    if page_directory()[pdi].is_extended() {
        return Some(page_directory()[pdi].phys() + (virt_addr & 0xfff_fff));
    }

    // If page is not mapped in page table, exit.
    if !page_table(pdi)[pti].is_present() {
        return None;
    }

    // Otherwise, get the page table entry and clear service bits.
    Some((page_table(pdi)[pti].0 & !0x3ff) + (virt_addr & 0xfff))
}

#[inline]
pub fn is_memory_accessible(addr: usize) -> bool {
    virt2phys(addr).is_some()
}
