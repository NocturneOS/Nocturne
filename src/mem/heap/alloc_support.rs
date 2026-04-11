use core::alloc::Layout;

use noct_tools::interrupt_locker::InterruptLocker;

use crate::{
    mem::heap::ArenaAllocator, qemu_log, sys::info::info,
};

/// Global allocator instance for the `alloc` crate
#[global_allocator]
static GLOBAL_ALLOCATOR: ArenaAllocator = ArenaAllocator::new();

const KERNEL_HEAP_START: usize = {
    #[cfg(target_arch = "x86")]
    {
        0xD000_0000
    }
    #[cfg(target_arch = "x86_64")]
    {
        0xFFFF_FFFF_A000_0000
    }
};

/// Initialize the global allocator with the available heap memory
///
/// This should be called once during kernel initialization, after
/// physical memory management and paging are set up.
pub fn init() {
    GLOBAL_ALLOCATOR.init(
        KERNEL_HEAP_START,
        0x0800_0000, //  0xD000_0000 .. 0xD800_0000
    );
}

pub unsafe fn allocate_no_map(layout: Layout) -> *mut u8 {
    let il = InterruptLocker::lock();

    let ptr = GLOBAL_ALLOCATOR
        .inner()
        .allocate_no_map(layout)
        .expect("Non-mapping allocation failed!")
        .as_ptr();

    drop(il);

    ptr
}

pub fn dump() {
    let il = InterruptLocker::lock();

    let lock = GLOBAL_ALLOCATOR.inner();

    for (n, i) in lock.blocks().iter().enumerate() {
        if i.address == 0 {
            break;
        }

        qemu_log!("#{n}: {:x?} - ({})", i.address, i.size);
    }

    drop(il);
}
