mod alloc_support;

// Re-export the init function for convenience
pub use alloc_support::{init, dump};

use core::alloc::{GlobalAlloc, Layout};
use core::ptr::{self, NonNull};
use core::usize;
use spin::{Mutex, MutexGuard};

use crate::arch::mem::paging::{self, PageFlags, map_single_page, unmap_single_page};
use crate::mem::physical;
use crate::{arch, qemu_log, tools};

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
        self.inner.try_lock().expect("Failed to acquire lock on heap initialization!").init(heap_start, heap_size)
    }

    fn inner<'t>(&'t self) -> MutexGuard<'t, InnerArenaAllocator> {
        let lock = self.inner.try_lock().expect("Heap locking failed!");
        // let lock = self.inner.lock();
        lock
    }
}

pub struct InnerArenaAllocator {
    arena: Option<&'static mut [Block]>,
    alloc_count: usize,
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
            heap_size: 0,
        }
    }

    /// Initialize the allocator with a heap region
    pub fn init(&mut self, heap_start: usize, heap_size: usize) {
        let page =
            physical::allocate_one().expect("Could not allocate an initial page for the heap!");

        map_single_page(page, heap_start, PAGE_FLAGS);

        // Now `heap_start` is our heap arena start.

        let entries_count = arch::get_page_size() / size_of::<Block>();

        qemu_log!("Heap: {entries_count} entries");

        let arena =
            unsafe { core::slice::from_raw_parts_mut(heap_start as *mut Block, entries_count) };

        arena.fill(unsafe { core::mem::zeroed() });

        // The first block is an arena itself. We allocated one page of memory for arena for now.
        arena[0].address = heap_start;
        arena[0].size = arch::get_page_size();

        self.alloc_count += 1;

        self.arena = Some(arena);

        self.heap_size = heap_size;
    }

    pub fn blocks<'a>(&'a self) -> &'a [Block] {
        self.arena
            .as_ref()
            .expect("Getting blocks on uninitialized allocator!")
    }

    // Returns Option<(INDEX, ADDRESS)>
    fn find_suitable_block(&self, layout: &Layout) -> Option<(usize, usize)> {
        let mut index = 0usize;

        for i in self.blocks().windows(2) {
            let this_block = &i[0];
            let next_block = &i[1];

            let this_block_end = this_block.address + this_block.size;

            let aligned_new_block_addr = tools::align_value(this_block_end, layout.align());

            if next_block.address == 0 && next_block.size == 0 {
                // Since we are at end of the block list, we have to increment the index to avoid last block overwrite.
                return Some((index + 1, aligned_new_block_addr));
            }

            if aligned_new_block_addr + layout.size() < next_block.address {
                return Some((index + 1, aligned_new_block_addr));
            }

            index += 1;
        }

        None
    }

    fn add_block(&mut self, index: usize, addr: usize, size: usize) {
        let arena = self.arena.as_mut().unwrap();

        arena.copy_within(index..self.alloc_count + 1, index + 1);

        arena[index] = Block {
            address: addr,
            size: size,
        };
    }

    fn remove_block(&mut self, index: usize) {
        let arena = self.arena.as_mut().unwrap();

        arena.copy_within(index + 1..self.alloc_count + 1, index);

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
        let start_addr = addr & !(arch::get_page_size() - 1);
        let end_addr = tools::align_value(addr + size, arch::get_page_size());

        for i in (start_addr..end_addr).step_by(arch::get_page_size()) {
            if !paging::is_memory_accessible(i) {
                // TODO: Cancel whole operation if page allocation fails and return None.
                let page = physical::allocate_one()
                    .expect("Failed to allocate a physical page during allocation.");

                map_single_page(page, i, PAGE_FLAGS);

                // qemu_log!("Page {page:x} allocated and mapped to {i:x}!");
            }
        }
    }

    // Checks that the region [ addr; addr + size ) doesn't overlap with other regions.
    // This method unmaps pages inside the region if it finds completely free pages.
    fn delicate_unmap_and_free(&self, addr: usize, size: usize, is_last_block: bool) {
        let page_size = arch::get_page_size();

        let lower_bound = tools::align_value(addr, page_size);
        let mut upper_bound = (addr + size) & !(page_size - 1);

        // qemu_log!("Aligned region: {:08x?}", lower_bound..upper_bound);

        // If we're checking last block, we do an inclusive free because there's no successor block ahead.
        // Since Range and RangeInclusive are different types, the other option is to make Range behave like it's inclusive.
        if is_last_block {
            upper_bound += page_size;
        }

        for i in (lower_bound..upper_bound).step_by(page_size) {
            if let Some(free_addr) = paging::virt2phys(i) {
                unmap_single_page(i);
                physical::free_one(free_addr);

                qemu_log!("Unmapped: V{:08x}", i);
                qemu_log!("Freed: P{:08x}", free_addr);
            }
        }
    }

    #[inline]
    fn is_last_block(&self, idx: usize) -> bool {
        idx == self.alloc_count - 1
    }

    fn ensure_arena_available(&mut self) {
        let old_arena_addr = self.arena.as_ref().unwrap().as_ptr().addr();
        let arena_len = self.arena.as_ref().unwrap().len();

        if self.alloc_count == arena_len - 2 {
            qemu_log!("Arena reallocation condition!");

            // New arena is two times bigger than old
            let new_arena_len = arena_len * 2;

            // Allocate memory
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

    /// Allocate memory with the given layout
    pub fn allocate(&mut self, layout: Layout) -> Option<NonNull<u8>> {
        self.ensure_arena_available();

        self.inner_allocate(layout)
    }

    /// Deallocate memory
    pub fn deallocate(&mut self, ptr: NonNull<u8>, layout: Layout) {
        let Some(idx) = self.find_block_by_address(ptr.addr().into()) else {
            panic!(
                "BUG: Deallocating a non-existent block! ({} of size {})",
                ptr.addr(),
                layout.size()
            );
        };

        self.remove_block(idx);

        if self.is_last_block(idx) {
            qemu_log!("{:08x} is a last block!", ptr.addr());
        }

        self.delicate_unmap_and_free(ptr.addr().into(), layout.size(), self.is_last_block(idx));

        self.alloc_count -= 1;
    }
}

unsafe impl GlobalAlloc for ArenaAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        self.inner()
            .allocate(layout)
            .map(|ptr| ptr.as_ptr())
            .unwrap_or(ptr::null_mut())
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if let Some(non_null_ptr) = NonNull::new(ptr) {
            self.inner().deallocate(non_null_ptr, layout);
        }
    }
}

unsafe impl Send for ArenaAllocator {}
unsafe impl Sync for ArenaAllocator {}
