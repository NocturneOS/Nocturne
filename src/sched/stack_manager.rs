use core::alloc::Layout;

use noct_spec::{KERNEL_BASE, WORD_SIZE};

use crate::{arch::{self, mem::paging::{GlobalPagingArchitecture, Page, PageFlags}}, qemu_log};
use crate::mem::address_space_manager::AddressSpace;

const STACK_ALIGNEMNT: usize = 0x1000;

#[repr(C)]
pub struct ThreadStack {
    pub(super) stack_pointer: usize,
    pub(super) stack_addr: usize,
    pub(super) stack_size: usize,
}

impl ThreadStack {
    pub fn new(size: usize) -> Self {
        let page_size = crate::arch::get_page_size();

        // We need a stack of size: requested_size + one page.
        // That one page will be a guard page, we'll unmap the first page of stack.
        // And when program exceeds the stack pointer, it will cause a Page Fault instead of rewriting data.
        let real_stack_size = size + page_size;

        // Allocate stack.
        let allocation = unsafe {
            alloc::alloc::alloc_zeroed(
                Layout::from_size_align(real_stack_size, STACK_ALIGNEMNT)
                    .expect("Stack layout creation failed!"),
            )
        } as *mut usize;

        // And calculate its pointer.
        let pointer = unsafe { allocation.byte_add(real_stack_size) };

        // Unmap the first page.
        crate::arch::mem::paging::unmap_single_page(allocation.addr());

        qemu_log!("Allocated a stack at: {allocation:?} with size: {real_stack_size:#x?} (ptr: {pointer:?})");

        Self {
            stack_pointer: pointer as usize,
            stack_size: size,
            stack_addr: allocation as usize,
        }
    }

    pub fn new_user(address_space: &mut AddressSpace<GlobalPagingArchitecture>, size: usize) -> Self {
        let page_size = crate::arch::get_page_size();
        let base_with_guard = address_space.alloc_virt_region(size + page_size);
        let mapped_base = base_with_guard + page_size; // guard page left unmapped

        // qemu_log!("Map from: {mapped_base:#x} to {:#x}", mapped_base + size);

        address_space.alloc_map_multiple_pages(
            mapped_base, size,
            PageFlags::Present | PageFlags::Writeable | PageFlags::Userspace,
        ).expect("stack mapping failed");

        Self {
            stack_pointer: mapped_base + size, // top of stack
            stack_addr: mapped_base,
            stack_size: size,
        }
    }

    pub fn from_existing(stack_ptr: *mut usize, size: usize, stack_addr: *mut usize) -> Self {
        Self {
            stack_pointer: stack_ptr as usize,
            stack_size: size,
            stack_addr: stack_addr as usize,
        }
    }

    pub unsafe fn pointer(&self) -> *mut usize {
        self.stack_pointer as *mut usize 
    }

    fn push_user(&mut self, address_space: &mut AddressSpace<GlobalPagingArchitecture>, value: usize) {
        let mut ptr = self.stack_pointer as *mut usize;

        ptr = unsafe { ptr.sub(1) };

        self.stack_pointer = ptr.addr();

        // 

        let index = (self.stack_pointer & 0xfff) / WORD_SIZE;
        
        // qemu_log!("Stack pointer: {:#x?}; Index: {};", self.stack_pointer, index);
        
        address_space.self_map_page_from_virt(self.stack_pointer & !0x3ff, |data| {
            data[index] = value;
        });
    }

    pub unsafe fn push(&mut self, address_space: &mut AddressSpace<GlobalPagingArchitecture>, value: usize) {
        if self.stack_pointer <= KERNEL_BASE {
            return self.push_user(address_space, value);
        }

        let mut ptr = self.stack_pointer as *mut usize;

        unsafe {
            ptr = ptr.sub(1);
            ptr.write(value);
        }

        self.stack_pointer = ptr.addr();
    }
}

impl Drop for ThreadStack {
    fn drop(&mut self) {
        if self.stack_addr < KERNEL_BASE {
            // We will free the stack in the sched/mod.rs instead, because we can't reach
            // AddressSpace here.

            return;
            //todo!("It's a user space stack, we need to deallocate it!");
        }

        // Now we creating a stack layout by using `_unchecked` kind of method,
        // because if we created a layout when creating a stack, it will 100% work on this stage too,
        // so we don't have to check.
        unsafe {
            alloc::alloc::dealloc(
                self.stack_addr as *mut u8,
                Layout::from_size_align_unchecked(self.stack_size, STACK_ALIGNEMNT),
            )
        };

        qemu_log!("Deallocated!");
    }
}
