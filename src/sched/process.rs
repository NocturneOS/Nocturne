use core::{cell::Cell, ffi::c_char, sync::atomic::{AtomicPtr, AtomicUsize, Ordering}};

use alloc::{ffi::CString};
use lazy_static::lazy_static;

use crate::qemu_log;

lazy_static! {
    static ref GLOBAL_PID: AtomicUsize = AtomicUsize::new(0);
}

#[repr(C)]
pub struct Process {
    pub id: usize,
    pub page_directory_phys: usize,
    pub page_directory_virt: usize,
    pub thread_count: AtomicUsize,
    pub name: AtomicPtr<c_char>,
    pub cwd: AtomicPtr<c_char>,
}

fn next_pid() -> usize {
    GLOBAL_PID.fetch_add(1, Ordering::SeqCst)
}

impl Process {
    pub fn new(pd_phys: usize, pd_virt: usize, name: &str, cwd: &str) -> Self {
        let name_ptr = CString::new(name).unwrap().into_raw();
        let cwd_ptr = CString::new(cwd).unwrap().into_raw();

        Self {
            id: next_pid(),
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
            qemu_log!("PROCESS DEALLOCATED!");

            drop(CString::from_raw(self.name.load(core::sync::atomic::Ordering::SeqCst)));
            drop(CString::from_raw(self.cwd.load(core::sync::atomic::Ordering::SeqCst)));
        }
    }
}
