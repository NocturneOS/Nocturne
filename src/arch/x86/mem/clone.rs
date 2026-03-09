use core::alloc::Layout;

use crate::{arch::{get_page_size, mem::paging::{self, PageFlags}}, mem::physical, qemu_log};

/// Clones kernel's paging root, it will just copy PDEs (shallow copy)
pub fn clone_kernel_page_root() -> usize {
    // This is a temporary block. We will map pages, work and unmap to it to reduce heap usage.
    let layout = Layout::from_size_align(get_page_size(), 0x1000).unwrap();
    let temporary_block = unsafe { alloc::alloc::alloc(layout) };

    let tb_phys = paging::virt2phys(temporary_block.addr()).unwrap();

    physical::free_one(tb_phys);

    paging::unmap_single_page(temporary_block.addr());

    let new_page_directory = crate::mem::physical::allocate_one().unwrap();

    paging::map_single_page(new_page_directory, temporary_block.addr(), PageFlags::Writeable | PageFlags::Present);

    unsafe { temporary_block.write_bytes(0, get_page_size()) };

    unsafe { (temporary_block as *mut usize).add(1023).write(new_page_directory | 3) };

    for i in 0..1023 {
        let pt = paging::page_directory()[i];

        if pt.is_present() {
            qemu_log!("[{:08x}] Available: {i} -> {:08x}", paging::indices2vaddr(i, 0), pt.phys());

            paging::map_single_page(new_page_directory, temporary_block.addr(), PageFlags::Writeable | PageFlags::Present);

            unsafe {
                (temporary_block as *mut usize).add(i).write(pt.raw());
            }
        }
    }

    // Clean up mappings.
    paging::unmap_single_page(temporary_block.addr());

    unsafe { alloc::alloc::dealloc(temporary_block, layout) };

    new_page_directory
}
