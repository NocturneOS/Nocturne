//! Physical memory manager

// Kernel memory layout:
// C000_0000: BIOS zone
// C010_0000: Kernel itself
// C010_0000 + KERNEL_SIZE: Physical memory bitmap

use crate::{arch::{self, get_page_size}, qemu_log, spec::WORD_SIZE_BITS};

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

    assert!(size % crate::spec::WORD_SIZE == 0);

    let length = size / crate::spec::WORD_SIZE;

    unsafe { core::slice::from_raw_parts_mut(rawptr, length) }
}

#[inline]
fn addr_to_indices(address: usize) -> (usize, usize) {
    assert!(address.is_multiple_of(arch::get_page_size()));

    let idx = address / (arch::get_page_size() * WORD_SIZE_BITS);
    let bitidx = (address / arch::get_page_size()) % WORD_SIZE_BITS;

    (idx, bitidx)
}

#[inline]
fn indices_to_addr(index: usize, bit_index: usize) -> usize {
    assert!(bit_index < WORD_SIZE_BITS);

    return ((index * WORD_SIZE_BITS) + bit_index) * arch::get_page_size()
}

fn is_used(address: usize) -> bool {
    let (idx, bitidx) = addr_to_indices(address);

    bitmap()[idx] & (1 << bitidx) != 0
}

/// Mark one page at `address` used or free.
fn mark_page(address: usize, is_used: bool) {
    let (idx, bitidx) = addr_to_indices(address);

    let data = bitmap()[idx];

    if is_used {
        bitmap_mut()[idx] = data | (1 << bitidx);
    } else {
        bitmap_mut()[idx] = data & !(1 << bitidx);
    }
}

/// Finds first free page
/// Returns an address in physical memory of free page
fn first_free_page() -> Option<usize> {
    for (n, i) in bitmap().iter().enumerate() {
        for nb in 0..WORD_SIZE_BITS {
            let element = i & (1 << nb);

            if element == 0 {
                return Some(indices_to_addr(n, nb));
            }
        }
    }

    None
}

/// Finds first cluster of free pages.
/// Returns an address in physical memory of free cluster
fn first_free_cluster(cluster_size: usize) -> Option<usize> {
    let mut counter = 0usize;
    let mut indices = (0usize, 0usize);
    let mut okay = false;

    // Now it's getting complex.
    // Introducing counter we ensure that we found a free cluster (counter == cluster_size)
    // With every iteration:
    // - If we found a free page we increment a counter and save starting page indices.
    // - If counter reached the requested size, convert indices to address and return it.
    // - If we found a used page, reset the counter.
    'main_loop: for (n, i) in bitmap().iter().enumerate() {
        for nb in 0..WORD_SIZE_BITS {
            let element = i & (1 << nb);

            if element == 0 {
                if counter == 0 {
                    indices = (n, nb);
                }

                counter += 1;
            } else {
                counter = 0;
            }

            // If we reached the end, break this loop.
            if counter == cluster_size {
                okay = true;
                break 'main_loop;
            }
        }
    }

    if okay {
        Some(indices_to_addr(indices.0, indices.1))
    } else {
        None
    }
}

/// Allocate one page of physical memory.
/// Returns an address in physical memory, guaranteed to be pagesize-aligned.
pub fn allocate_one() -> Option<usize> {
    let first_free = first_free_page()?;

    mark_page(first_free, true);

    Some(first_free)
}

/// Allocate one page of physical memory.
/// Returns an address in physical memory, guaranteed to be pagesize-aligned.
pub fn allocate_bulk(page_count: usize) -> Option<usize> {
    let first_free = first_free_cluster(page_count)?;

    qemu_log!("Bulk found first free block: {:x} (with page count: {})", first_free, page_count);

    for i in 0..page_count {
        let addr = first_free + (i * arch::get_page_size());

        mark_page(addr, true);
    }

    Some(first_free)
}

pub fn free_one(address: usize) {
    mark_page(address, false);
}

pub fn free_bulk(address: usize, page_count: usize) {
    for i in 0..page_count {
        mark_page(address + (i * arch::get_page_size()), false);
    }
}

pub fn init() {
    // Zero out the bitmap, marking all memory as free.

    bitmap_mut().fill(0);

    qemu_log!("Bitmap size: {} bytes", bitmap().len() * crate::spec::WORD_SIZE);
    qemu_log!("Bitmap length: {}", bitmap().len());
}
