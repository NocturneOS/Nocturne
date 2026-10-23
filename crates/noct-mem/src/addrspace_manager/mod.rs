use core::{alloc::Layout, marker::PhantomData};

use crate::{
    addrspace_manager::page_allocation::PageAllocation, heap, paging::{self, PagingHierarchy, unmap_pages}
};
use alloc::vec::Vec;
use noct_logger::qemu_log;
use noct_spec::{USER_SPACE_TOP, WORD_SIZE};

use crate::paging::{Page, PageFlags, map_single_page, unmap_single_page};

pub mod page_allocation;

#[derive(Debug)]
pub struct AddressSpaceVirtualBlock {
    address: usize,
    size: usize,
}

/// Address space. It's a representation of CR3 paging root, that can be edited.
/// It uses temporary interprocess mappings to access their physical regions.
#[repr(C)]
pub struct AddressSpace<PG: PagingHierarchy> {
    phantom: PhantomData<PG>,

    pub page_root_phys: usize,

    // Allocator VMA.
    pub(super) used_virt_areas: Vec<AddressSpaceVirtualBlock>,

    /// Whether this address space owns `page_root_phys` and all page tables
    /// reachable from the user-space half of the root.
    ///
    /// `false` for the kernel address space (`predefined`) and for uninitialized
    /// instances, because their root is shared with the boot code/kernel.
    owns_root: bool,
}

impl<PG: PagingHierarchy> AddressSpace<PG> {
    pub fn new() -> Self {
        let areas = Vec::with_capacity(1024);
        let root = paging::clone::clone_kernel_page_root::<PG>();

        Self {
            page_root_phys: root,
            used_virt_areas: areas,
            owns_root: true,

            phantom: PhantomData,
        }
    }

    pub fn uninitialized() -> Self {
        Self {
            page_root_phys: 0,
            used_virt_areas: Vec::new(),
            owns_root: false,

            phantom: PhantomData,
        }
    }

    pub fn predefined(phys: usize) -> Self {
        Self {
            page_root_phys: phys,
            used_virt_areas: Vec::new(),
            owns_root: false,

            phantom: PhantomData,
        }
    }

    pub fn is_uninitialized(&self) -> bool {
        self.page_root_phys == 0
    }

    /// Returns `true` if this address space's root is currently loaded in CR3.
    fn is_loaded(&self) -> bool {
        let current = unsafe { x86::controlregs::cr3() } as usize;

        (current & !(crate::paging::PAGE_SIZE - 1))
            == (self.page_root_phys & !(crate::paging::PAGE_SIZE - 1))
    }

    /// Invalidates the TLB entry for `virt_addr` if we are modifying the
    /// address space that is currently loaded.
    ///
    /// Modifications to another process' page tables don't need an explicit
    /// flush: the CPU will not have cached translations for that CR3 while it
    /// is not loaded.
    fn flush_tlb_for(&self, virt_addr: usize) {
        if self.is_loaded() {
            unsafe { x86::tlb::flush(virt_addr) };
        }
    }

    pub fn root_physical_addr(&self) -> usize {
        self.page_root_phys
    }

    pub fn self_map_page<T>(&self, phys_addr: usize, f: impl FnOnce(&mut [Page]) -> T) -> T {
        let layout = Layout::from_size_align(
            crate::paging::PAGE_SIZE,
            crate::paging::PAGE_SIZE,
        )
        .unwrap();
        let mapping_region = unsafe { heap::allocate_no_map(layout) };

        map_single_page(
            phys_addr,
            mapping_region.addr(),
            PageFlags::Present | PageFlags::Writeable,
        );

        let slice = unsafe {
            core::slice::from_raw_parts_mut(
                mapping_region as *mut Page,
                crate::paging::PAGE_SIZE / WORD_SIZE,
            )
        };

        let result = f(slice);

        unmap_single_page(mapping_region.addr());

        unsafe { alloc::alloc::dealloc(mapping_region, layout) };

        result
    }

    pub fn self_map_data<T>(&self, phys_allocation: &PageAllocation, f: impl FnOnce(&mut [u8]) -> T) -> T {
        let byte_count = crate::paging::PAGE_SIZE * phys_allocation.page_count();
        let layout = Layout::from_size_align(
            byte_count,
            crate::paging::PAGE_SIZE,
        )
        .unwrap();
        let mapping_region = unsafe { heap::allocate_no_map(layout) };

        for (i, page_phys) in phys_allocation.pages().enumerate() {
            map_single_page(
                page_phys,
                mapping_region.addr() + (i * crate::paging::PAGE_SIZE),
                PageFlags::Present | PageFlags::Writeable,
            );
        }

        let slice = unsafe {
            core::slice::from_raw_parts_mut(
                mapping_region as *mut u8,
                byte_count,
            )
        };

        let result = f(slice);

        unmap_pages(mapping_region.addr(), byte_count);

        unsafe { alloc::alloc::dealloc(mapping_region, layout) };

        result
    }

    pub fn self_map_page_from_virt<T>(
        &self,
        virt_addr: usize,
        f: impl FnOnce(&mut [usize]) -> T,
    ) -> T {
        let layout = Layout::from_size_align(crate::paging::PAGE_SIZE, 0x1000).unwrap();
        let mapping_region = unsafe { heap::allocate_no_map(layout) };

        // Map paging root and get physical address of virtual one.
        let phys = self.phys_of_virt(virt_addr).unwrap();
        let phys_page = phys & !(crate::paging::PAGE_SIZE - 1);

        map_single_page(
            phys_page,
            mapping_region.addr(),
            PageFlags::Present | PageFlags::Writeable,
        );

        let slice = unsafe {
            core::slice::from_raw_parts_mut(
                mapping_region as *mut usize,
                crate::paging::PAGE_SIZE / WORD_SIZE,
            )
        };

        let result = f(slice);

        unmap_single_page(mapping_region.addr());

        unsafe { alloc::alloc::dealloc(mapping_region, layout) };

        result
    }

    // FIXME: Check the control flow on `?`
    pub fn map_single_page(
        &mut self,
        phys_addr: usize,
        virt_addr: usize,
        flags: PageFlags,
    ) -> Result<(), ()> {
        assert!(
            phys_addr.is_multiple_of(crate::paging::PAGE_SIZE),
            "Physical address is not page-aligned: {phys_addr:#x?}"
        );
        assert!(
            virt_addr.is_multiple_of(crate::paging::PAGE_SIZE),
            "Virtual address is not page-aligned: {virt_addr:#x?}"
        );

        if virt_addr >= USER_SPACE_TOP {
            panic!(
                "Attempted to map a page outside of user space! ({:#x?})",
                virt_addr
            );
        }

        let mut pr = self.page_root_phys;

        for level in 0..PG::LEVELS - 1 {
            let idx = PG::index_at_level(virt_addr, level);

            pr = self.self_map_page(pr, |page_table| {
                let pt_phys: usize;

                if !page_table[idx].is_present() {
                    // FIXME: Possible memory leak on Err(())
                    pt_phys = noct_physmem_alloc::allocate_one().ok_or(())?;

                    self.self_map_page(pt_phys, |x| {
                        x.fill(Page::null());
                    });

                    page_table[idx] = Page::new(
                        pt_phys,
                        PageFlags::Present | PageFlags::Writeable | PageFlags::Userspace,
                    );

                    qemu_log!("New page table mapped at level {level} for virt addr {virt_addr:#x?} at phys addr {pt_phys:#x?}");
                } else {
                    if flags.contains(PageFlags::Userspace) && !page_table[idx].is_usermode() {
                        qemu_log!("{:#x?} (level {level}) set to usermode. ({:#x?} -> {:#x?})", page_table[idx].raw(), phys_addr, virt_addr);

                        page_table[idx].set_usermode(true);
                    }

                    pt_phys = page_table[idx].phys();
                }

                Ok(pt_phys)
            })?;
        }

        let leaf_idx = PG::index_at_level(virt_addr, PG::LEVELS - 1);

        self.self_map_page(pr, |page_table| {
            page_table[leaf_idx] =
                Page::new(phys_addr, PageFlags::Present | flags | PageFlags::Userspace);
        });

        self.flush_tlb_for(virt_addr);

        Ok(())
    }

    pub fn unmap_single_page(&mut self, virt_addr: usize) {
        assert!(
            virt_addr.is_multiple_of(crate::paging::PAGE_SIZE),
            "Virtual address is not page-aligned: {virt_addr:#x?}"
        );

        if virt_addr >= USER_SPACE_TOP {
            panic!(
                "Attempted to unmap a page outside of user space! ({:#x?})",
                virt_addr
            );
        }

        let mut pr = Some(self.page_root_phys);

        for level in 0..PG::LEVELS - 1 {
            let idx = PG::index_at_level(virt_addr, level);

            pr = self.self_map_page(pr.unwrap(), |page_table| {
                if !page_table[idx].is_present() {
                    return None;
                }

                Some(page_table[idx].phys())
            });

            if pr.is_none() {
                return;
            }
        }

        let leaf_idx = PG::index_at_level(virt_addr, PG::LEVELS - 1);

        self.self_map_page(pr.unwrap(), |page_table| {
            page_table[leaf_idx] = Page::null();
        });

        self.flush_tlb_for(virt_addr);
    }

    pub fn unmap_pages(&mut self, virt_addr: usize, size: usize) {
        assert!(virt_addr.is_multiple_of(crate::paging::PAGE_SIZE));

        let page_count = size.div_ceil(crate::paging::PAGE_SIZE);

        for i in 0..page_count {
            self.unmap_single_page(virt_addr + (i * crate::paging::PAGE_SIZE));
        }
    }

    pub fn map_pages(
        &mut self,
        phys_addr: usize,
        virt_addr: usize,
        size: usize,
        flags: PageFlags,
    ) -> Result<(), ()> {
        assert!(phys_addr.is_multiple_of(crate::paging::PAGE_SIZE));
        assert!(virt_addr.is_multiple_of(crate::paging::PAGE_SIZE));

        let page_count = size.div_ceil(crate::paging::PAGE_SIZE);

        let mut mapped = 0;

        for i in 0..page_count {
            if let Err(e) = self.map_single_page(
                phys_addr + (i * crate::paging::PAGE_SIZE),
                virt_addr + (i * crate::paging::PAGE_SIZE),
                flags,
            ) {
                // Roll back the mappings we already installed. Physical pages
                // themselves are owned by the caller (e.g. `PageAllocation`),
                // so only unmap them here.
                for j in 0..mapped {
                    self.unmap_single_page(virt_addr + (j * crate::paging::PAGE_SIZE));
                }

                return Err(e);
            }

            mapped += 1;
        }

        Ok(())
    }

    pub fn map_pages_pa(
        &mut self,
        pa: &PageAllocation,
        virt_addr: usize,
        flags: PageFlags,
    ) -> Result<(), ()> {
        for (i, phys) in pa.pages().enumerate() {
            self.map_single_page(
                phys,
                virt_addr + (i * crate::paging::PAGE_SIZE),
                flags,
            )?;
        }

        Ok(())
    }

    pub fn unmap_pages_pa(
        &mut self,
        pa: &PageAllocation,
        virt_addr: usize,
    ) -> Result<(), ()> {
        for i in 0..pa.page_count() {
            self.unmap_single_page(
                virt_addr + (i * crate::paging::PAGE_SIZE),
            );
        }

        Ok(())
    }

    /// Number of bytes covered by a huge page at `level` (only valid for
    /// `level < PG::LEVELS - 1`).
    fn huge_page_size(level: usize) -> usize {
        let index_bits = PG::ENTRIES.trailing_zeros() as usize;

        crate::paging::PAGE_SIZE << (index_bits * (PG::LEVELS - 1 - level))
    }

    /// Translates `virt_addr` through this address space.
    ///
    /// Returns a physical address including the offset inside the page. For a
    /// regular 4 KiB mapping the low 12 bits are preserved; for huge page
    /// mappings the offset inside the huge page is preserved as well.
    pub fn phys_of_virt(&self, virt_addr: usize) -> Option<usize> {
        if virt_addr >= USER_SPACE_TOP {
            return None;
        }

        let mut current_table_phys = self.page_root_phys;

        for level in 0..PG::LEVELS {
            let idx = PG::index_at_level(virt_addr, level);

            let entry = self.self_map_page(current_table_phys, |table| table[idx]);

            if !entry.is_present() {
                return None;
            }

            if level + 1 == PG::LEVELS {
                // Normal 4 KiB mapping: `entry.phys()` is page-aligned, so
                // adding the offset is safe.
                return Some(entry.phys() + (virt_addr & (crate::paging::PAGE_SIZE - 1)));
            }

            if entry.is_extended() {
                // Huge page mapping (2 MiB/1 GiB on x86_64, 4 MiB on x86).
                let huge_size = Self::huge_page_size(level);

                return Some(entry.phys() + (virt_addr & (huge_size - 1)));
            }

            current_table_phys = entry.phys();
        }

        None
    }

    pub fn alloc_map_single_page(&mut self, virt_addr: usize, flags: PageFlags) -> Result<usize, ()> {
        let page = noct_physmem_alloc::allocate_one().ok_or(())?;

        if let Err(e) = self.map_single_page(page, virt_addr, flags) {
            noct_physmem_alloc::free_one(page);

            return Err(e);
        }

        Ok(page)
    }

    /// Bulk allocates and maps physical pages to `(virt_addr..virt_addr + size_in_bytes)` range.
    #[must_use]
    pub fn alloc_map_multiple_pages(
        &mut self,
        virt_addr: usize,
        size_in_bytes: usize,
        flags: PageFlags,
    ) -> Result<PageAllocation, ()> {
        let page_count = size_in_bytes.div_ceil(crate::paging::PAGE_SIZE);

        // Try allocate pages in bulk.
        {
            let physical = noct_physmem_alloc::allocate_bulk(page_count);

            if let Some(phys) = physical {
                if let Err(e) = self.map_pages(phys, virt_addr, size_in_bytes, flags) {
                    // `map_pages` already unmapped the pages it managed to map.
                    noct_physmem_alloc::free_bulk(phys, page_count);

                    return Err(e);
                }

                return Ok(PageAllocation::Bulk { addr: phys, page_count });
            }
        }

        // If it didn't work, let's try allocating one by one.
        let mut pages: Vec<usize> = Vec::with_capacity(page_count);

        for i in 0..page_count {
            let Some(page) = noct_physmem_alloc::allocate_one() else {
                // Allocation failed in the middle: revert everything.
                for (j, allocated) in pages.iter().enumerate() {
                    self.unmap_single_page(virt_addr + (j * crate::paging::PAGE_SIZE));
                    noct_physmem_alloc::free_one(*allocated);
                }

                return Err(());
            };

            if let Err(e) = self.map_single_page(
                page,
                virt_addr + (i * crate::paging::PAGE_SIZE),
                flags,
            ) {
                noct_physmem_alloc::free_one(page);

                for (j, allocated) in pages.iter().enumerate() {
                    self.unmap_single_page(virt_addr + (j * crate::paging::PAGE_SIZE));
                    noct_physmem_alloc::free_one(*allocated);
                }

                return Err(e);
            }

            pages.push(page);
        }

        Ok(PageAllocation::Multiple(pages))
    }

    /// Allocates the virtual region of specified `size`.
    ///
    /// The size is rounded up to a page. Returns `None` if the size is zero,
    /// overflows, or if the user virtual address space is exhausted.
    pub fn alloc_virt_region(&mut self, size: usize) -> Option<usize> {
        if size == 0 {
            return None;
        }

        let size = size
            .div_ceil(crate::paging::PAGE_SIZE)
            .checked_mul(crate::paging::PAGE_SIZE)?;

        if size >= USER_SPACE_TOP {
            return None;
        }

        if self.used_virt_areas.is_empty() {
            let addr = USER_SPACE_TOP.checked_sub(size)?;
            self.used_virt_areas.push(AddressSpaceVirtualBlock {
                address: addr,
                size,
            });
            return Some(addr);
        }

        // Check the gap between USER_SPACE_TOP and the topmost block.
        {
            let first = &self.used_virt_areas[0];
            let first_end = first.address.checked_add(first.size)?;
            let gap = USER_SPACE_TOP.checked_sub(first_end)?;

            if gap >= size {
                let addr = USER_SPACE_TOP.checked_sub(size)?;
                self.used_virt_areas.insert(
                    0,
                    AddressSpaceVirtualBlock {
                        address: addr,
                        size,
                    },
                );
                return Some(addr);
            }
        }

        // Scan gaps between consecutive blocks (list is high-low).
        for i in 0..self.used_virt_areas.len().saturating_sub(1) {
            let upper_addr = self.used_virt_areas[i].address;
            let lower = &self.used_virt_areas[i + 1];
            let lower_end = lower.address.checked_add(lower.size)?;
            let gap = upper_addr.checked_sub(lower_end)?;

            if gap >= size {
                let addr = upper_addr.checked_sub(size)?;
                self.used_virt_areas.insert(
                    i + 1,
                    AddressSpaceVirtualBlock {
                        address: addr,
                        size,
                    },
                );
                return Some(addr);
            }
        }

        // No gap found - extend below the lowest block.
        let addr = self
            .used_virt_areas
            .last()?
            .address
            .checked_sub(size)?;

        self.used_virt_areas.push(AddressSpaceVirtualBlock {
            address: addr,
            size,
        });

        Some(addr)
    }

    /// Releases a region previously returned by [`Self::alloc_virt_region`].
    ///
    /// Returns `false` if no region starts at `address`. This is a programming
    /// error, but it is reported instead of panicking because the address can
    /// come from userspace.
    pub fn free_virt_region(&mut self, address: usize) -> bool {
        let Some(idx) = self
            .used_virt_areas
            .iter()
            .position(|block| block.address == address)
        else {
            return false;
        };

        self.used_virt_areas.remove(idx);

        true
    }
    /// Recursively frees the page tables reachable from the user-space half of
    /// `table_phys`, starting at `level` (0 = paging root).
    ///
    /// Leaf frames are intentionally NOT freed here: their ownership belongs to
    /// a `PageAllocation` (ELF segments, thread stacks) or to another subsystem
    /// (e.g. `sbrk` currently leaks them with `mem::forget`). Freeing them here
    /// would double-free pages that are still tracked elsewhere, and would also
    /// try to return MMIO frames (e.g. a framebuffer) to the physical allocator.
    fn release_page_tables(&self, table_phys: usize, level: usize) {
        if level >= PG::LEVELS {
            return;
        }

        self.self_map_page(table_phys, |table| {
            // At the root level only the user-space entries are owned by this
            // address space. The kernel half is shared with every address space.
            let entry_count = if level == 0 {
                PG::user_root_entry_count()
            } else {
                PG::ENTRIES
            };

            for entry in table.iter().take(entry_count) {
                if !entry.is_present() {
                    continue;
                }

                if level + 1 == PG::LEVELS {
                    // Leaf mapping; see the comment on this function.
                    continue;
                }

                if entry.is_extended() {
                    // Huge page (leaf), not a page table.
                    continue;
                }

                let child_table = entry.phys();

                if child_table == 0 {
                    continue;
                }

                self.release_page_tables(child_table, level + 1);

                noct_physmem_alloc::free_one(child_table);
            }
        });
    }
}

impl<PG: PagingHierarchy> Drop for AddressSpace<PG> {
    fn drop(&mut self) {
        // `predefined` (the kernel address space) must never have its root or
        // its shared kernel page tables released.
        if !self.owns_root || self.page_root_phys == 0 {
            return;
        }

        // We must not pull page tables out from under the CPU. Dead tasks are
        // normally reaped from the kernel thread, so this is only a safety net.
        if self.is_loaded() {
            qemu_log!(
                "AddressSpace {:?} is being dropped while loaded, leaking its page tables!",
                self.page_root_phys
            );

            return;
        }

        self.release_page_tables(self.page_root_phys, 0);

        noct_physmem_alloc::free_one(self.page_root_phys);
    }
}
