use core::alloc::Layout;

use crate::{
    arch::{
        self,
        mem::paging::{Page, PageFlags, map_single_page, unmap_single_page, vaddr2indices},
    },
    mem::physical::{self, allocate_bulk, allocate_one, free_one},
    spec::WORD_SIZE,
};

pub struct AddressSpace {
    pub page_root_phys: usize,

    // Bump allocator VMA.
    pub(super) next_free_virt_addr: usize
}

impl AddressSpace {
    pub fn new() -> Self {
        let root = super::clone::clone_kernel_page_root();

        Self {
            page_root_phys: root,
            next_free_virt_addr: crate::spec::KERNEL_BASE,
        }
    }

    pub fn uninitialized() -> Self {
        Self {
            page_root_phys: 0,
            next_free_virt_addr: crate::spec::KERNEL_BASE,
        }
    }

    pub fn predefined(phys: usize) -> Self {
        Self {
            page_root_phys: phys,
            next_free_virt_addr: crate::spec::KERNEL_BASE,
        }
    }

    pub fn is_uninitialized(&self) -> bool {
        self.page_root_phys == 0
    }

    pub fn root_physical_addr(&self) -> usize {
        self.page_root_phys
    }

    pub fn self_map_page<T>(&self, addr: usize, f: impl FnOnce(&mut [Page]) -> T) -> T {
        let layout = Layout::from_size_align(arch::get_page_size(), 0x1000).unwrap();
        let mapping_region = unsafe { alloc::alloc::alloc(layout) };

        map_single_page(
            addr,
            mapping_region.addr(),
            PageFlags::Present | PageFlags::Writeable,
        );

        let slice = unsafe {
            core::slice::from_raw_parts_mut(
                mapping_region as *mut Page,
                arch::get_page_size() / WORD_SIZE,
            )
        };

        let result = f(slice);

        unmap_single_page(mapping_region.addr());

        unsafe { alloc::alloc::dealloc(mapping_region, layout) };

        result
    }

    pub fn self_map_page_from_virt<T>(&self, virt_addr: usize, f: impl FnOnce(&mut [usize]) -> T) -> T {
        let layout = Layout::from_size_align(arch::get_page_size(), 0x1000).unwrap();
        let mapping_region = unsafe { alloc::alloc::alloc(layout) };

        let phys = self.self_map_page(self.page_root_phys, |data| {
            let (pdi, pti) = vaddr2indices(virt_addr);

            let pt_phys = data[pdi];

            self.self_map_page(pt_phys.phys(), |pt| {
                pt[pti].phys()
            })
        });

        map_single_page(
            phys,
            mapping_region.addr(),
            PageFlags::Present | PageFlags::Writeable,
        );

        let slice = unsafe {
            core::slice::from_raw_parts_mut(
                mapping_region as *mut usize,
                arch::get_page_size() / WORD_SIZE,
            )
        };

        let result = f(slice);

        unmap_single_page(mapping_region.addr());

        unsafe { alloc::alloc::dealloc(mapping_region, layout) };

        result
    }

    // FIXME: Check the control flow on `?`
    pub fn map_single_page(&mut self, phys_addr: usize, virt_addr: usize, flags: PageFlags) -> Result<(), ()> {
        if virt_addr >= crate::spec::KERNEL_BASE {
            panic!("Attemped to map pages on a kernel region! ({:#x?})", virt_addr);
        }

        self.self_map_page(self.page_root_phys, |page_root| {
            let (pdi, pti) = vaddr2indices(virt_addr);

            if !page_root[pdi].is_present() {
                let page_table = allocate_one().ok_or(())?;

                page_root[pdi] = Page::new(
                    page_table,
                    PageFlags::Present | PageFlags::Writeable | PageFlags::Userspace,
                );
            }

            let pt_phys = page_root[pdi].phys();

            self.self_map_page(pt_phys, |page_table| {
                page_table[pti] = Page::new(
                    phys_addr,
                    PageFlags::Present | flags | PageFlags::Userspace,
                );
            });

            Ok(())
        })
    }

    pub fn unmap_single_page(&mut self, phys_addr: usize, virt_addr: usize) {
        self.self_map_page(self.page_root_phys, |page_root| {
            let (pdi, pti) = vaddr2indices(virt_addr);

            if !page_root[pdi].is_present() {
                return;
            }

            let pt_phys = page_root[pdi].phys();

            self.self_map_page(pt_phys, |page_table| {
                page_table[pti] = Page::null();
            });
        });
    }

    pub fn unmap_pages(&mut self, phys_addr: usize, virt_addr: usize, size: usize) {
        assert!(phys_addr.is_multiple_of(arch::get_page_size()));
        assert!(virt_addr.is_multiple_of(arch::get_page_size()));

        let page_count = size.div_ceil(arch::get_page_size());

        for i in 0..page_count {
            self.unmap_single_page(
                phys_addr + (i * arch::get_page_size()),
                virt_addr + (i * arch::get_page_size()),
            );
        }
    }

    pub fn map_pages(&mut self, phys_addr: usize, virt_addr: usize, size: usize, flags: PageFlags) -> Result<(), ()> {
        assert!(phys_addr.is_multiple_of(arch::get_page_size()));
        assert!(virt_addr.is_multiple_of(arch::get_page_size()));

        let page_count = size.div_ceil(arch::get_page_size());

        for i in 0..page_count {
            self.map_single_page(
                phys_addr + (i * arch::get_page_size()),
                virt_addr + (i * arch::get_page_size()),
                flags
            )?;
        }

        Ok(())
    }

    pub fn alloc_map_single_page(&mut self, virt_addr: usize, flags: PageFlags) -> Result<(), ()> {
        let page = allocate_one().ok_or(())?;

        self.map_single_page(page, virt_addr, flags)?;

        Ok(())
    }

    /// Bulk allocates and maps pages in `(virt_addr..virt_addr + size_in_bytes)` range.
    pub fn alloc_map_multiple_pages(&mut self, virt_addr: usize, size_in_bytes: usize, flags: PageFlags) -> Result<(), ()> {
        let page_count = size_in_bytes.div_ceil(arch::get_page_size());

        // Try allocate pages in bulk.
        {
            let physical = allocate_bulk(page_count);

            if let Some(phys) = physical {
                self.map_pages(phys, virt_addr, size_in_bytes, flags)?;

                return Ok(());
            }
        }

        // If it didn't work, let's try allocating one by one.
        {
            for i in 0..page_count {
                // FIXME: Handle allocation error. We can't use `?`, because if this happens in the middle ...
                // ... of the loop, it will remain some pages mapped, but we have to revert this operation completely.

                let page = allocate_one().unwrap();

                self.map_single_page(page, virt_addr + (i * arch::get_page_size()), flags).unwrap();
            }
        }

        Ok(())
    }

    /// Allocates a region of virtual memory. (Growing down)
    /// Returns the starting address of the region.
    pub fn alloc_virt_region(&mut self, size: usize) -> usize {
        let page_size: usize = arch::get_page_size();
        let aligned = size.next_multiple_of(page_size);

        self.next_free_virt_addr -= aligned;
        self.next_free_virt_addr
    }
}

impl Drop for AddressSpace {
    fn drop(&mut self) {
        self.self_map_page(self.page_root_phys, |page_root| {
            // This region (0..768) is dedicated to user-space memory.
            for i in 0..768 {
                if page_root[i].is_present() {
                    let real_address = page_root[i].phys();

                    // Free all the entries in the page table before freeing it.
                    self.self_map_page(real_address, |page_table| {
                        for i in page_table {
                            if i.is_present() {
                                free_one(i.phys());
                            }
                        }
                    });

                    physical::free_one(real_address);
                }
            }
        });
    }
}
