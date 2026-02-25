use core::alloc::Layout;

use crate::qemu_log;

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
        // TODO: Set some flags to make difference between `Non-Present` page and `Guard` page.
        crate::arch::mem::paging::unmap_single_page(allocation.addr());

        qemu_log!("Allocated a stack at: {allocation:?} with size: {real_stack_size:#x?} (ptr: {pointer:?})");

        Self {
            stack_pointer: pointer as usize,
            stack_size: size,
            stack_addr: allocation as usize,
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

    pub unsafe fn push(&mut self, value: usize) {
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
