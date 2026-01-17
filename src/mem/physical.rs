//! Physical memory manager

// Kernel memory layout:
// C000_0000: BIOS zone
// C010_0000: Kernel itself
// C010_0000 + KERNEL_SIZE: Physical memory bitmap

use crate::qemu_log;

unsafe extern "C" {
    static IMAGE_VIRT_END: *const ();
}

fn bitmap() -> &'static [usize] {
    let rawptr = (unsafe { &IMAGE_VIRT_END } as *const *const ()).addr() as *const usize;

    // Size - in bytes; Length - in items.
    let size = crate::sys::info::info().physical_memory_bitmap_size.unwrap();

    assert!(size % crate::spec::WORD_SIZE == 0);

    let length = size / crate::spec::WORD_SIZE;

    unsafe { core::slice::from_raw_parts(rawptr, length) }
}

fn bitmap_mut() -> &'static mut [usize] {
    let rawptr = (unsafe { &IMAGE_VIRT_END } as *const *const ()).addr() as *mut usize;

    // Size - in bytes; Length - in items.
    let size = crate::sys::info::info().physical_memory_bitmap_size.unwrap();

    assert!(size % crate::spec::WORD_SIZE != 0);

    let length = size / crate::spec::WORD_SIZE;

    unsafe { core::slice::from_raw_parts_mut(rawptr, length) }
}

pub fn init() {
    qemu_log!("Bitmap size: {} bytes", bitmap().len() * crate::spec::WORD_SIZE);
    qemu_log!("Bitmap length: {}", bitmap().len());
}
