mod alloc_support;

// Re-export the init function for convenience
pub use alloc_support::{allocate_no_map, init, heap_bounds};
use noct_logger::qemu_log;
use noct_tools::interrupt_locker::InterruptLocker;

use core::alloc::{GlobalAlloc, Layout};
use core::ops::Range;
use core::ptr::{self, NonNull};
use spin::{Mutex, MutexGuard};

use crate::paging::{self, PageFlags};

/// Page flags for kernel heap: Present + Writable
///
/// WTH with the code I could use `PageFlags::Present | PageFlags::Writeable`, but it's not a `const` operation.
const PAGE_FLAGS: PageFlags = PageFlags::Present.union(PageFlags::Writeable);

pub struct ArenaAllocator {
    inner: Mutex<InnerArenaAllocator>,
}

impl ArenaAllocator {
    pub const fn new() -> Self {
        Self {
            inner: Mutex::new(InnerArenaAllocator::new()),
        }
    }

    pub fn init(&self, heap_start: usize, heap_size: usize) {
        self.inner
            .try_lock()
            .expect("Failed to acquire lock on heap initialization!")
            .init(heap_start, heap_size)
    }

    fn inner(&self) -> MutexGuard<'_, InnerArenaAllocator> {
        let lock = self.inner.try_lock().expect("Heap locking failed!");
        // let lock = self.inner.lock();
        lock
    }
}

pub struct InnerArenaAllocator {
    arena: Option<&'static mut [Block]>,
    alloc_count: usize,
    heap_start: usize,
    heap_size: usize,
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct Block {
    pub address: usize,
    pub size: usize,
}

impl InnerArenaAllocator {
    /// Create a new uninitialized allocator
    pub const fn new() -> Self {
        Self {
            arena: None,
            alloc_count: 0,
            heap_start: 0,
            heap_size: 0,
        }
    }

    /// Initialize the allocator with a heap region
    pub fn init(&mut self, heap_start: usize, heap_size: usize) {
        let page = noct_physmem_alloc::allocate_one()
            .expect("Could not allocate an initial page for the heap!");

        paging::map_single_page(page, heap_start, PAGE_FLAGS);

        // Now `heap_start` is our heap arena start.

        let entries_count = crate::paging::PAGE_SIZE / size_of::<Block>();

        qemu_log!("Heap: {entries_count} entries");

        let arena =
            unsafe { core::slice::from_raw_parts_mut(heap_start as *mut Block, entries_count) };

        arena.fill(unsafe { core::mem::zeroed() });

        // The first block is an arena itself. We allocated one page of memory for arena for now.
        arena[0].address = heap_start;
        arena[0].size = crate::paging::PAGE_SIZE;

        self.alloc_count += 1;

        self.arena = Some(arena);

        self.heap_start = heap_start;
        self.heap_size = heap_size;

        qemu_log!("Heap at: P{page:#x?} -> V{heap_start:#x?} with size: {heap_size:.} bytes");
    }

    pub fn blocks(&self) -> &[Block] {
        self.arena
            .as_ref()
            .expect("Getting blocks on uninitialized allocator!")
    }

    fn dump(&self) {
        for (n, i) in self.blocks().iter().enumerate() {
            if i.address == 0 {
                break;
            }

            qemu_log!("#{n}: {:x?} - ({})", i.address, i.size);
        }
    }

    // Returns Option<(INDEX, ADDRESS)>
    fn find_suitable_block(&self, layout: &Layout) -> Option<(usize, usize)> {
        for (index, i) in self.blocks().windows(2).enumerate() {
            let this_block = &i[0];
            let next_block = &i[1];

            let this_block_end = if let Some(a) = this_block.address.checked_add(this_block.size) {
                a
            } else {
                self.dump();

                panic!(
                    "Failed to `+` {:#x?} and {} (index = {index})",
                    this_block.address, this_block.size
                );
            };

            let aligned_new_block_addr = noct_tools::align_value(this_block_end, layout.align());

            if next_block.address == 0 && next_block.size == 0 {
                // Since we are at end of the block list, we have to increment the index to avoid last block overwrite.
                return Some((index + 1, aligned_new_block_addr));
            }

            if aligned_new_block_addr + layout.size() < next_block.address {
                return Some((index + 1, aligned_new_block_addr));
            }
        }

        None
    }

    fn add_block(&mut self, index: usize, addr: usize, size: usize) {
        let arena = self.arena.as_mut().unwrap();

        if self.alloc_count > arena.len() {
            panic!("Arena overflow!");
        }

        arena.copy_within(index..self.alloc_count + 1, index + 1);

        arena[index] = Block {
            address: addr,
            size,
        };
    }

    fn remove_block(&mut self, index: usize) {
        let arena = self.arena.as_mut().unwrap();

        arena.copy_within(index + 1..=self.alloc_count, index);

        arena[self.alloc_count] = unsafe { core::mem::zeroed() };
    }

    fn find_block_by_address(&self, addr: usize) -> Option<usize> {
        let mut idx: Option<usize> = None;

        for (n, i) in self.blocks().iter().enumerate() {
            if i.address == 0 && i.size == 0 {
                break;
            }

            if i.address == addr {
                idx = Some(n);
                break;
            }
        }

        idx
    }

    /// Ensures that the region [ addr; addr + size ) is accessible.
    /// If region within the range above is not accessible, allocate a physical page and map it.
    fn ensure_mapped(&self, addr: usize, size: usize) {
        let start_addr = addr & !(crate::paging::PAGE_SIZE - 1);
        let end_addr = noct_tools::align_value(addr + size, crate::paging::PAGE_SIZE);

        for i in (start_addr..end_addr).step_by(crate::paging::PAGE_SIZE) {
            if !paging::is_memory_accessible(i) {
                // TODO: Cancel whole operation if page allocation fails and return None.
                let page = noct_physmem_alloc::allocate_one()
                    .expect("Failed to allocate a physical page during allocation.");

                paging::map_single_page(page, i, PAGE_FLAGS);

                // qemu_log!("Page {page:x} allocated and mapped to {i:x}!");
            }
        }
    }

    // Checks that the region [ addr; addr + size ) doesn't overlap with other regions.
    // This method unmaps pages inside the region if it finds completely free pages.
    fn delicate_unmap_and_free(&self, addr: usize, size: usize, is_last_block: bool) {
        let page_size = crate::paging::PAGE_SIZE;
        let page_mask = page_size - 1;

        // Start freeing from the first page boundary at or after addr (if addr is page-aligned)
        let lower_bound = if addr & page_mask == 0 {
            addr
        } else {
            (addr + page_mask) & !page_mask // rounding up
        };

        // End freeing at the last page boundary before or at addr + size
        let end_addr = addr + size;
        let mut upper_bound = if end_addr & page_mask == 0 && !is_last_block {
            end_addr // Page-aligned end, but exclude this page (next block might start here)
        } else {
            noct_tools::align_down(end_addr, page_size)
        };

        // For last block, we can safely include the final page if end is page-aligned
        if is_last_block && (end_addr & page_mask == 0) {
            upper_bound = end_addr;
        }

        for i in (lower_bound..upper_bound).step_by(page_size) {
            if let Some(free_addr) = paging::virt2phys(i) {
                paging::unmap_single_page(i);

                noct_physmem_alloc::free_one(free_addr);
            }
        }
    }

    #[inline]
    fn is_last_block(&self, idx: usize) -> bool {
        idx == self.alloc_count - 1
    }

    // Ensures that we have enough space in arena to insert new block.
    fn ensure_arena_available(&mut self) {
        let (old_arena_addr, arena_len) = {
            let arena = self.arena.as_ref().expect("No arena, it's a bug!");
            
            (arena.as_ptr().addr(), arena.len())
        };

        // Why `-2`? Because with `-1` we convert length to index of last element,
        // and another `-1` ensures that if condition below confirms, we can place a block with new arena there.
        if self.alloc_count == arena_len - 2 {
            qemu_log!("Arena reallocation condition!");

            // New arena is two times bigger than old
            let new_arena_len = arena_len * 2;

            // Allocate memory in old arena.
            let block = self
                .inner_allocate(Layout::array::<Block>(new_arena_len).unwrap())
                .unwrap()
                .as_ptr() as *mut Block;

            // Convert it to slice
            let new_arena = unsafe { core::slice::from_raw_parts_mut(block, new_arena_len) };

            // And copy all old entries from old to new.
            new_arena[..arena_len].copy_from_slice(self.arena.as_ref().unwrap());

            // Set the new arena.
            self.arena = Some(new_arena);

            // And free the old arena.
            self.deallocate(
                NonNull::new(old_arena_addr as *mut u8).unwrap(),
                Layout::array::<Block>(arena_len).unwrap(),
            );
        }
    }

    fn inner_allocate(&mut self, layout: Layout) -> Option<NonNull<u8>> {
        let (index, address) = self.find_suitable_block(&layout)?;

        self.ensure_mapped(address, layout.size());

        self.add_block(index, address, layout.size());

        self.alloc_count += 1;

        NonNull::new(address as *mut u8)
    }

    fn inner_allocate_no_map(&mut self, layout: Layout) -> Option<NonNull<u8>> {
        let (index, address) = self.find_suitable_block(&layout)?;

        self.add_block(index, address, layout.size());

        self.alloc_count += 1;

        NonNull::new(address as *mut u8)
    }

    /// Allocate memory with the given layout
    pub fn allocate(&mut self, layout: Layout) -> Option<NonNull<u8>> {
        self.ensure_arena_available();

        self.inner_allocate(layout)
    }

    /// Allocate memory with the given layout without mapping it
    pub fn allocate_no_map(&mut self, layout: Layout) -> Option<NonNull<u8>> {
        debug_assert!(
            layout.align().is_multiple_of(crate::paging::PAGE_SIZE),
            "Non-mapping allocation must be PAGESIZE-multiple aligned."
        );

        self.ensure_arena_available();

        self.inner_allocate_no_map(layout)
    }

    /// Deallocate memory
    pub fn deallocate(&mut self, ptr: NonNull<u8>, layout: Layout) {
        let Some(idx) = self.find_block_by_address(ptr.addr().into()) else {
            panic!(
                "BUG: Deallocating a non-existent block! ({:#x?} of size {})",
                ptr.addr(),
                layout.size()
            );
        };

        self.remove_block(idx);

        let is_last_block = self.is_last_block(idx);

        // if is_last_block {
        //     qemu_log!("{:p} is a last block!", ptr);
        // }

        self.delicate_unmap_and_free(ptr.addr().into(), layout.size(), is_last_block);

        self.alloc_count -= 1;
    }

    pub fn heap_bounds(&self) -> Range<usize> {
        let start_addr = self.heap_start;
        let end_addr = start_addr + self.heap_size;

        (start_addr..end_addr)
    }
}

unsafe impl GlobalAlloc for ArenaAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let il = InterruptLocker::lock();

        let block: *mut u8 = self
            .inner()
            .allocate(layout)
            .map(|ptr| ptr.as_ptr())
            .unwrap_or(ptr::null_mut());

        debug_assert!(block.addr().is_multiple_of(layout.align()));

        drop(il);

        block
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        let il = InterruptLocker::lock();

        if let Some(non_null_ptr) = NonNull::new(ptr) {
            self.inner().deallocate(non_null_ptr, layout);
        }

        drop(il);
    }
}
