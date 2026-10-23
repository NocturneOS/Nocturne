use core::alloc::Layout;

use crate::paging::{PageFlags, PagingHierarchy};

/// Clones kernel's paging root, it will just copy PDEs (shallow copy)
/// I can't get the kernel process that has exactly kernel-only page directories/tables, so just copy from current CR3.
/// Returns a physical addr of paging root (a value to load into CR3)
pub fn clone_kernel_page_root<PG: PagingHierarchy>() -> usize {
    // This is a temporary block. We will map pages, work and unmap to it to reduce heap usage.
    let layout = Layout::from_size_align(crate::paging::PAGE_SIZE, 0x1000).unwrap();
    let temporary_block = unsafe { crate::heap::allocate_no_map(layout) };

    let new_page_directory = noct_physmem_alloc::allocate_one().unwrap();

    crate::paging::map_single_page(
        new_page_directory,
        temporary_block.addr(),
        PageFlags::Writeable | PageFlags::Present,
    );

    unsafe { temporary_block.write_bytes(0, crate::paging::PAGE_SIZE) };

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

        let mut entry = root[i];

        if entry.is_present() {
            // Clear Accessed and Dirty flags.
            entry.set_flags(entry.flags() & !(PageFlags::Accessed | PageFlags::Dirty));

            unsafe {
                (temporary_block as *mut usize).add(i).write(entry.raw());
            }
        }
    }

    // Clean up mappings.
    crate::paging::unmap_single_page(temporary_block.addr());

    unsafe { alloc::alloc::dealloc(temporary_block, layout) };

    new_page_directory
}
