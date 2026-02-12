use core::{cell::Cell, ffi::c_char, sync::atomic::{AtomicPtr, AtomicUsize}};

use alloc::{ffi::CString};

#[repr(C)]
pub struct Process {
    pub id: usize,
    pub page_directory_phys: usize,
    pub page_directory_virt: usize,
    pub thread_count: AtomicUsize,
    pub name: AtomicPtr<c_char>,
    pub cwd: AtomicPtr<c_char>,
}

impl Process {
    pub fn new(id: usize, pd_phys: usize, pd_virt: usize, name: &str, cwd: &str) -> Self {
        let name_ptr = CString::new(name).unwrap().into_raw();
        let cwd_ptr = CString::new(cwd).unwrap().into_raw();

        Self {
            id,
            page_directory_phys: pd_phys,
            page_directory_virt: pd_virt,
            thread_count: 0.into(),
            name: name_ptr.into(),
            cwd: cwd_ptr.into()
        }
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        unsafe {
            drop(CString::from_raw(self.name.load(core::sync::atomic::Ordering::SeqCst)));
            drop(CString::from_raw(self.cwd.load(core::sync::atomic::Ordering::SeqCst)));
        }
    }
}
