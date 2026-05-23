use core::alloc::Layout;

use crate::paging::{PageFlags, PagingHierarchy};

/// Clones kernel's paging root, it will just copy PDEs (shallow copy)
pub fn clone_kernel_page_root<PG: PagingHierarchy>() -> usize {
    // This is a temporary block. We will map pages, work and unmap to it to reduce heap usage.
    let layout = Layout::from_size_align(super::PAGE_SIZE, 0x1000).unwrap();
    let temporary_block = unsafe { crate::heap::allocate_no_map(layout) };

    let new_page_directory = noct_physmem_alloc::allocate_one().unwrap();

    super::map_single_page(
        new_page_directory,
        temporary_block.addr(),
        PageFlags::Writeable | PageFlags::Present,
    );

    unsafe { temporary_block.write_bytes(0, super::PAGE_SIZE) };

    unsafe {
        (temporary_block as *mut usize)
            .add(PG::RECURSIVE_INDEX)
            .write(new_page_directory | 3)
    };

    let root = PG::root();

    for i in 0..PG::ENTRIES {
        if i == PG::RECURSIVE_INDEX {
            continue; // already written it
        }

        let entry = root[i];

        // if entry.is_present() {
        if (entry & PageFlags::Present.bits()) != 0 {
            unsafe {
                (temporary_block as *mut usize).add(i).write(entry);
            }
        }
    }

    // Clean up mappings.
    super::unmap_single_page(temporary_block.addr());

    unsafe { alloc::alloc::dealloc(temporary_block, layout) };

    new_page_directory
}
