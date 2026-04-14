use crate::{arch::get_page_size, qemu_log};
use bitflags::bitflags;
use noct_paging::PagingHierarchy;
use noct_spec::WORD_SIZE;

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

#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, PartialOrd)]
pub struct Page(usize);

impl Page {
    pub fn new(phys_addr: usize, flags: PageFlags) -> Self {
        Self(phys_addr | flags.bits())
    }

    pub fn null() -> Self {
        Self(0)
    }

    pub fn raw(&self) -> usize {
        self.0
    }

    pub fn phys(&self) -> usize {
        self.0 & !0xfff
    }

    pub fn flags(&self) -> PageFlags {
        PageFlags::from_bits(self.0 & 0x1FF).unwrap()
    }

    pub fn is_present(&self) -> bool {
        self.flags().contains(PageFlags::Present)
    }

    pub fn is_writeable(&self) -> bool {
        self.flags().contains(PageFlags::Writeable)
    }

    pub fn is_extended(&self) -> bool {
        self.flags().contains(PageFlags::Extended)
    }
}

impl PartialEq<usize> for Page {
    fn eq(&self, other: &usize) -> bool {
        self.0 == *other
    }
}

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
            _ => unreachable!()
        }
    }

    // 0x0000_0000 - 0xC000_0000
    fn user_root_entry_count() -> usize { 768 }

    fn root() -> &'static [usize] {
        unsafe { core::slice::from_raw_parts(0xFFFF_F000 as *const usize, 1023) }
    }
}

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

    let table_flags = PageFlags::Present | PageFlags::Writeable | 
                  (flags & PageFlags::Userspace);

    if pt == 0 {
        let new_pt = noct_physmem_alloc::allocate_one().unwrap();

        page_directory_mut()[pdi] = Page(new_pt | table_flags.bits());

        let page_table = page_table_mut(pdi);
        page_table.fill(Page::null());
    }

    let page_table = page_table_mut(pdi);

    page_table[pti] = Page(physical_address | flags.bits() | 1);

    unsafe { x86::tlb::flush(virtual_address) };

    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
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

#[inline]
pub fn is_memory_accessible(addr: usize) -> bool {
    virt2phys(addr).is_some()
}

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
    qemu_log!("Pages: {:?}", available_memory_size / PAGE_SIZE);

    // Divide memory by pages and then by 8 (bits in one byte) - it's the bitmap size.
    let mut phys_bitmap_size = (available_memory_size / PAGE_SIZE) / 8;

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

        qemu_log!("PD[{n}] = {:#x}", i.raw());
    }

    qemu_log!("Finished");
}
