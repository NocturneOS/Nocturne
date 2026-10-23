use crate::{addrspace_manager::AddressSpace, paging::{PageFlags, PagingHierarchy}};

#[derive(Debug)]
pub enum HeapError {
    AccessBeyondLimits,
    AddressSpaceFail,
    AddressOverflow
}

pub struct Heap<PG: PagingHierarchy> {
    phantom: core::marker::PhantomData<PG>,

    heap_base: usize,     // fixed at process creation (after BSS)
    heap_end: usize,      // current break, grows upward
    heap_max: usize,      // reserved limit, e.g. next VMA-eligible region start
}

impl<PG: PagingHierarchy> Heap<PG> {
    pub fn new(heap_base: usize, heap_max: usize) -> Self {
        let heap_base = heap_base.next_multiple_of(crate::get_page_size());
        let heap_max = heap_max.next_multiple_of(crate::get_page_size());

        Self {
            phantom: core::marker::PhantomData,
            heap_base,
            heap_end: heap_base,
            heap_max,
        }
    }

    pub fn base(&self) -> usize {
        self.heap_base
    }

    pub fn end(&self) -> usize {
        self.heap_end
    }

    pub fn max(&self) -> usize {
        self.heap_max
    }

    pub fn sbrk(&mut self, addrspace: &mut AddressSpace<PG>, increment: isize) -> Result<usize, HeapError> {
        let old_end = self.heap_end;
        let new_end = old_end.checked_add_signed(increment).ok_or(HeapError::AddressOverflow)?;

        if new_end > self.heap_max || new_end < self.heap_base {
            return Err(HeapError::AccessBeyondLimits);
        }

        let page_size = crate::get_page_size();
        let old_top = old_end.next_multiple_of(page_size);
        let new_top = new_end.next_multiple_of(page_size);

        if new_top > old_top {
            let pa = addrspace.alloc_map_multiple_pages(
                old_top, new_top - old_top,
                PageFlags::Present | PageFlags::Writeable | PageFlags::Userspace,
            ).map_err(|_| HeapError::AddressSpaceFail)?;

            // SAFETY: This page allocation manages only pages, but kernel will lose them if it gets out of the scope.
            //         But the area will be still mapped.
            //         The next `else if` branch will handle freeing physical pages soon.
            core::mem::forget(pa);
        } else if new_top < old_top {
            // TODO: Free physical pages.
            addrspace.unmap_pages(new_top, old_top - new_top);
        }

        self.heap_end = new_end;
        Ok(old_end) // sbrk() returns the *previous* break
    }
}