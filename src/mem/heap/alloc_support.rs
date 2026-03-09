use crate::{mem::heap::ArenaAllocator, qemu_log, sys::info::info, tools::interrupt_locker::InterruptLocker};

/// Global allocator instance for the `alloc` crate
#[global_allocator]
static GLOBAL_ALLOCATOR: ArenaAllocator = ArenaAllocator::new();

const KERNEL_HEAP_START: usize = {
    #[cfg(target_arch = "x86")] {
        0xD000_0000
    }
    #[cfg(target_arch = "x86_64")] {
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
        0x0800_0000,  //  0xD000_0000 .. 0xD800_0000
    );
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
