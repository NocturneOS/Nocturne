use core::ops::{Deref, DerefMut};

use alloc::vec::Vec;
use noct_mem::addrspace_manager::page_allocation::PageAllocation;

#[derive(Debug)]
pub struct LoadInfo {
    pub physical_allocation: PageAllocation,
    pub virtual_addr: usize,
    pub page_count: usize,
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