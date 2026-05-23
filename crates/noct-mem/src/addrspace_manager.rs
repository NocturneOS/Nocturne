use core::{alloc::Layout, marker::PhantomData};

use crate::{
    heap,
    paging::{self, PagingHierarchy},
};
use alloc::vec::Vec;
use noct_logger::qemu_log;
use noct_spec::{KERNEL_BASE, WORD_SIZE};

use crate::paging::{Page, PageFlags, map_single_page, unmap_single_page};

#[derive(Debug)]
pub struct AddressSpaceVirtualBlock {
    address: usize,
    size: usize,
}

/// Address space. It's a representation of CR3 paging root, that can be edited.
/// It uses temporary mappings to access physical regions.
#[repr(C)]
pub struct AddressSpace<PG: PagingHierarchy> {
    phantom: PhantomData<PG>,

    pub page_root_phys: usize,

    // Allocator VMA.
    pub(super) used_virt_areas: Vec<AddressSpaceVirtualBlock>,
}

impl<PG: PagingHierarchy> AddressSpace<PG> {
    pub fn new() -> Self {
        let areas = Vec::with_capacity(1024);
        let root = paging::clone::clone_kernel_page_root::<PG>();

        Self {
            page_root_phys: root,
            used_virt_areas: areas,

            phantom: PhantomData,
        }
    }

    pub fn uninitialized() -> Self {
        Self {
            page_root_phys: 0,
            used_virt_areas: Vec::new(),

            phantom: PhantomData,
        }
    }

    pub fn predefined(phys: usize) -> Self {
        Self {
            page_root_phys: phys,
            used_virt_areas: Vec::new(),

            phantom: PhantomData,
        }
    }

    pub fn is_uninitialized(&self) -> bool {
        self.page_root_phys == 0
    }

    pub fn root_physical_addr(&self) -> usize {
        self.page_root_phys
    }

    pub fn self_map_page<T>(&self, phys_addr: usize, f: impl FnOnce(&mut [Page]) -> T) -> T {
        let layout = Layout::from_size_align(crate::paging::PAGE_SIZE, 0x1000).unwrap();
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

    pub fn self_map_page_from_virt<T>(
        &self,
        virt_addr: usize,
        f: impl FnOnce(&mut [usize]) -> T,
    ) -> T {
        let layout = Layout::from_size_align(crate::paging::PAGE_SIZE, 0x1000).unwrap();
        let mapping_region = unsafe { heap::allocate_no_map(layout) };

        // Map paging root and get physical address of virtual one.
        let phys = self.phys_of_virt(virt_addr).unwrap();

        map_single_page(
            phys,
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
        if virt_addr >= KERNEL_BASE {
            panic!(
                "Attemped to map pages on a kernel region! ({:#x?})",
                virt_addr
            );
        }

        let mut pr = self.page_root_phys;

        for level in 0..PG::LEVELS - 1 {
            let idx = PG::index_at_level(virt_addr, level);

            pr = self.self_map_page(pr, |page_table| {
                let pt_phys: usize;

                if !page_table[idx].is_present() {
                    pt_phys = noct_physmem_alloc::allocate_one().ok_or(())?;

                    self.self_map_page(pt_phys, |x| {
                        x.fill(Page::null());
                    });

                    page_table[idx] = Page::new(
                        pt_phys,
                        PageFlags::Present | PageFlags::Writeable | PageFlags::Userspace,
                    );
                } else {
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

        Ok(())
    }

    pub fn unmap_single_page(&mut self, virt_addr: usize) {
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

        for i in 0..page_count {
            self.map_single_page(
                phys_addr + (i * crate::paging::PAGE_SIZE),
                virt_addr + (i * crate::paging::PAGE_SIZE),
                flags,
            )?;
        }

        Ok(())
    }

    pub fn phys_of_virt(&self, virt_addr: usize) -> Option<usize> {
        let mut current_table_phys = self.page_root_phys;

        for level in 0..PG::LEVELS {
            let idx = PG::index_at_level(virt_addr, level);

            qemu_log!("PG: {virt_addr:08x} level {level} is {idx}");

            current_table_phys = self.self_map_page(current_table_phys, |table| {
                let entry = table[idx];

                if entry.is_present() {
                    Some(entry.phys())
                } else {
                    None
                }
            })?;
        }

        Some(current_table_phys)

        // qemu_log!("Current table: {:08x}", current_table_phys);

        // let leaf_idx = PG::index_at_level(virt_addr, PG::LEVELS - 1);

        // qemu_log!("LEAF PG: {virt_addr:08x} level {} is {leaf_idx}", PG::LEVELS - 1);

        // self.self_map_page(current_table_phys, |table| {
        //     let entry = table[leaf_idx];

        //     if entry.is_present() {
        //         Some(entry.phys())
        //     } else {
        //         None
        //     }
        // })
    }

    pub fn alloc_map_single_page(&mut self, virt_addr: usize, flags: PageFlags) -> Result<(), ()> {
        let page = noct_physmem_alloc::allocate_one().ok_or(())?;

        self.map_single_page(page, virt_addr, flags)?;

        Ok(())
    }

    /// Bulk allocates and maps pages in `(virt_addr..virt_addr + size_in_bytes)` range.
    pub fn alloc_map_multiple_pages(
        &mut self,
        virt_addr: usize,
        size_in_bytes: usize,
        flags: PageFlags,
    ) -> Result<(), ()> {
        let page_count = size_in_bytes.div_ceil(crate::paging::PAGE_SIZE);

        // Try allocate pages in bulk.
        {
            let physical = noct_physmem_alloc::allocate_bulk(page_count);

            if let Some(phys) = physical {
                self.map_pages(phys, virt_addr, size_in_bytes, flags)?;

                return Ok(());
            }
        }

        // If it didn't work, let's try allocating one by one.
        {
            for i in 0..page_count {
                // TODO: Handle allocation error. We can't use `?`, because if this happens in the middle ...
                // ... of the loop, it will remain some pages mapped, but we have to revert this operation completely.

                let page = noct_physmem_alloc::allocate_one().unwrap();

                self.map_single_page(page, virt_addr + (i * crate::paging::PAGE_SIZE), flags)
                    .unwrap();
            }
        }

        Ok(())
    }

    // Maybe Result<usize, ASVAllocationError>?
    pub fn alloc_virt_region(&mut self, size: usize) -> usize {
        if self.used_virt_areas.is_empty() {
            let addr = KERNEL_BASE - size;
            self.used_virt_areas.push(AddressSpaceVirtualBlock {
                address: addr,
                size,
            });
            return addr;
        }

        // Check the gap between KERNEL_BASE and the topmost block.
        {
            let first = &self.used_virt_areas[0];
            let gap = KERNEL_BASE - (first.address + first.size);
            if gap >= size {
                let addr = KERNEL_BASE - size;
                self.used_virt_areas.insert(
                    0,
                    AddressSpaceVirtualBlock {
                        address: addr,
                        size,
                    },
                );
                return addr;
            }
        }

        // Scan gaps between consecutive blocks (list is high-low).
        for i in 0..self.used_virt_areas.len() - 1 {
            let upper_addr = self.used_virt_areas[i].address;
            let lower_end = self.used_virt_areas[i + 1].address + self.used_virt_areas[i + 1].size;
            let gap = upper_addr - lower_end;

            if gap >= size {
                let addr = upper_addr - size;
                self.used_virt_areas.insert(
                    i + 1,
                    AddressSpaceVirtualBlock {
                        address: addr,
                        size,
                    },
                );
                return addr;
            }
        }

        // No gap found - extend below the lowest block.
        let addr = self.used_virt_areas.last().unwrap().address - size;
        self.used_virt_areas.push(AddressSpaceVirtualBlock {
            address: addr,
            size,
        });
        addr
    }

    pub fn free_virt_region(&mut self, address: usize) {
        let mut index: Option<usize> = None;

        for (idx, block) in self.used_virt_areas.iter().enumerate() {
            if block.address == address {
                index = Some(idx);
                break;
            }
        }

        if let Some(idx) = index {
            self.used_virt_areas.remove(idx);
        } else {
            panic!("Tried to free nonexistent block in ASVA: {address:#x?}");
        }
    }
}

impl<PG: PagingHierarchy> Drop for AddressSpace<PG> {
    fn drop(&mut self) {
        let mut physial_addresses = [0usize; 1024];

        self.self_map_page(self.page_root_phys, |page_root| {
            // This region (0..user_root_entry_count) is dedicated to user-space memory.
            for i in 0..PG::user_root_entry_count() {
                if page_root[i].is_present() {
                    let real_address = page_root[i].phys();

                    physial_addresses[i] = real_address;
                }
            }
        });

        for real_address in physial_addresses.iter().filter(|&&x| x != 0) {
            // Free all the entries in the page table before freeing it.
            self.self_map_page(*real_address, |page_table| {
                for i in page_table {
                    // qemu_log!("Checking address: {i:x?}");

                    if i.raw() >= 0x1000 && i.is_present() {
                        noct_physmem_alloc::free_one(i.phys());
                    }
                }
            });

            noct_physmem_alloc::free_one(*real_address);
        }
    }
}
