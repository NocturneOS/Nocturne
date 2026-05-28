use core::ops::{Deref, DerefMut};

use alloc::vec::Vec;
use noct_mem::addrspace_manager::page_allocation::PageAllocation;

#[derive(Debug)]
pub struct LoadInfo {
    pub(crate) physical_allocation: PageAllocation,
    pub(crate) virtual_addr: usize,
    pub(crate) page_count: usize,
}

#[derive(Debug, Default)]
pub struct LoadedSegments {
    segs: Vec<LoadInfo>
}

impl LoadedSegments {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Deref for LoadedSegments {
    type Target = Vec<LoadInfo>;

    fn deref(&self) -> &Self::Target {
        &self.segs
    }
}

impl DerefMut for LoadedSegments {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.segs
    }
}

// impl Drop for LoadedSegments {
//     fn drop(&mut self) {
//         for seg in &self.segs {
//             for page in 0..seg.page_count {
//                 noct_mem::paging::unmap_single_page(
//                     (seg.virtual_addr + (page * noct_mem::paging::PAGE_SIZE as usize)) as _,
//                 )
//             }

//             noct_physmem_alloc::free_bulk(seg.physical_allocation as _, seg.page_count as _);
//         }
//     }
// }