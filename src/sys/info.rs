use lazy_static::lazy_static;
use spin::{RwLock, RwLockReadGuard, RwLockWriteGuard};

#[derive(Debug, Default)]
pub struct SystemInfo {
    pub kernel_start: usize,
    pub kernel_end: usize,

    pub installed_memory: Option<usize>,

    pub physical_memory_bitmap_size: Option<usize>,
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
