use crate::{addrspace_manager::AddressSpace, paging::{PageFlags, PagingHierarchy}};

pub struct Heap<PG: PagingHierarchy> {
    phantom: core::marker::PhantomData<PG>,

    heap_base: usize,     // fixed at process creation (after BSS)
    heap_end: usize,      // current break, grows upward
    heap_max: usize,      // reserved limit, e.g. next VMA-eligible region start
}

impl<PG: PagingHierarchy> Heap<PG> {
    pub fn new(heap_base: usize, heap_max: usize) -> Self {
        Self {
            phantom: core::marker::PhantomData,
            heap_base,
            heap_end: heap_base,
            heap_max,
        }
    }

    pub fn sbrk(&mut self, addrspace: &mut AddressSpace<PG>, increment: isize) -> Result<usize, ()> {
        let old_end = self.heap_end;
        let new_end = old_end.checked_add_signed(increment).ok_or(())?;

        if new_end > self.heap_max || new_end < self.heap_base {
            return Err(());
        }

        let page_size = crate::get_page_size();
        let old_top = old_end.next_multiple_of(page_size);
        let new_top = new_end.next_multiple_of(page_size);

        if new_top > old_top {
            addrspace.alloc_map_multiple_pages(
                old_top, new_top - old_top,
                PageFlags::Present | PageFlags::Writeable | PageFlags::Userspace,
            )?;
        } else if new_top < old_top {
            addrspace.unmap_pages(new_top, old_top - new_top);
        }

        self.heap_end = new_end;
        Ok(old_end) // sbrk() returns the *previous* break
    }
}