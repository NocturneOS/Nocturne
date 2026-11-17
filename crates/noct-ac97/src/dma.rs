//! Page aligned allocations that can be handed to the AC'97 DMA engine.

use core::{alloc::Layout, ptr::NonNull};

/// A heap allocation with an explicit layout.
///
/// The AC'97 bus master works with physical addresses, so allocations used by
/// it must be page aligned to guarantee that every BDL entry stays inside a
/// single physical page.
pub struct DmaAllocation {
    ptr: NonNull<u8>,
    layout: Layout,
}

impl DmaAllocation {
    pub fn zeroed(size: usize, align: usize) -> Option<Self> {
        let layout = Layout::from_size_align(size, align).ok()?;
        let ptr = unsafe { alloc::alloc::alloc_zeroed(layout) };

        NonNull::new(ptr).map(|ptr| Self { ptr, layout })
    }

    pub fn ptr(&self) -> *mut u8 {
        self.ptr.as_ptr()
    }

    pub fn len(&self) -> usize {
        self.layout.size()
    }

    pub fn phys_at(&self, offset: usize) -> Option<usize> {
        debug_assert!(offset < self.len());

        noct_mem::paging::virt2phys_precise(self.ptr.as_ptr() as usize + offset)
    }
}

impl Drop for DmaAllocation {
    fn drop(&mut self) {
        unsafe { alloc::alloc::dealloc(self.ptr.as_ptr(), self.layout) };
    }
}
