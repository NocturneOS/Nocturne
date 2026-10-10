#![no_std]

use lazy_static::lazy_static;
use noct_cmdline_parser::Cmdline;
use spin::{RwLock, RwLockReadGuard, RwLockWriteGuard};

#[derive(Debug, Default)]
pub struct SystemInfo {
    // Addresses of kernel bounds extracted from the linker script definitions.
    pub kernel_start: usize,
    pub kernel_end: usize,

    // Kernel end with bootloader modules included
    pub kernel_area_end: usize,

    // System installed memory size.
    pub installed_memory: Option<usize>,

    // Bitmap size.
    pub physical_memory_bitmap_size: Option<usize>,

    // The free zone that is usually needed for heap.
    pub available_memory_start: Option<usize>,

    pub kernel_cmdline: Option<Cmdline>
}

lazy_static! {
    static ref SYSTEM_INFO: RwLock<SystemInfo> = RwLock::new(SystemInfo::default());
}

pub fn info() -> RwLockReadGuard<'static, SystemInfo> {
    SYSTEM_INFO.read()
}

pub fn info_mut() -> RwLockWriteGuard<'static, SystemInfo> {
    SYSTEM_INFO.write()
}
