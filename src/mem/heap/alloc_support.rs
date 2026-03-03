use crate::{mem::heap::ArenaAllocator, qemu_log, sys::info::info};

/// Global allocator instance for the `alloc` crate
#[global_allocator]
static GLOBAL_ALLOCATOR: ArenaAllocator = ArenaAllocator::new();

/// Initialize the global allocator with the available heap memory
///
/// This should be called once during kernel initialization, after
/// physical memory management and paging are set up.
pub fn init() {
    let available_size = info().installed_memory.unwrap() - info().available_memory_start.unwrap();

    GLOBAL_ALLOCATOR.init(
        0xD000_0000,
        available_size,
    );
}

pub fn dump() {
    let lock = GLOBAL_ALLOCATOR.inner();

    for (n, i) in lock.blocks().iter().enumerate() {
        if i.address == 0 {
            break;
        }

        qemu_log!("#{n}: {:x?} - ({})", i.address, i.size);
    }
}
