#![no_std]

extern crate alloc;

pub mod addrspace_manager;
pub mod heap;
pub mod paging;

pub fn get_page_size() -> usize {
    paging::PAGE_SIZE
}