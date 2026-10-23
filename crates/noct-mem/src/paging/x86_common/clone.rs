use core::alloc::Layout;

use crate::paging::{PageFlags, PagingHierarchy};

/// Clones kernel's paging root, it will just copy the kernel entries (shallow copy).
/// The user half of the new root is left empty, so every address space gets its
/// own user page tables.
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
    let end = core::cmp::min(root.len(), PG::ENTRIES);

    // Only copy the kernel-owned half. Copying user entries from the current
    // CR3 would make the parent and the child share page tables if this is ever
    // called while a user address space is loaded (e.g. a future fork/spawn).
    for i in PG::user_root_entry_count()..end {
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
