use core::{
    ffi::c_char, sync::atomic::{AtomicPtr, AtomicUsize, Ordering}
};

use alloc::ffi::CString;
use lazy_static::lazy_static;
use noct_sync::pseudosync::PseudoSync;

use crate::{arch::mem::paging::{GlobalPagingArchitecture, PageFlags}, qemu_log};
use crate::mem::address_space_manager::AddressSpace;

lazy_static! {
    static ref GLOBAL_PID: AtomicUsize = AtomicUsize::new(0);
}

#[repr(C)]
pub struct Process {
    pub id: usize,
    pub address_space: PseudoSync<AddressSpace<GlobalPagingArchitecture>>,

    // SAFE ZONE
    pub thread_count: AtomicUsize,
    pub name: AtomicPtr<c_char>,
    pub cwd: AtomicPtr<c_char>,
}

#[cfg(target_arch = "x86")]
const _: &[()] = &[
    assert!(core::mem::offset_of!(Process, id) == 0),
    assert!(core::mem::offset_of!(Process, address_space) == 4),
];

fn next_pid() -> usize {
    GLOBAL_PID.fetch_add(1, Ordering::SeqCst)
}

impl Process {
    pub fn new(name: &str, cwd: &str) -> Self {
        let name_ptr = CString::new(name).unwrap().into_raw();
        let cwd_ptr = CString::new(cwd).unwrap().into_raw();

        // TEST SUITE!!!
        let mut address_space = AddressSpace::<GlobalPagingArchitecture>::new();

        // qemu_log!("MAPPING...");

        // address_space.map_pages(
        //     0x100_000,
        //     0x4010_0000,
        //     0x20_0000,
        //     PageFlags::Present | PageFlags::Writeable | PageFlags::Userspace
        // );

        // qemu_log!("MAPPED!");

        Self {
            id: next_pid(),
            address_space: address_space.into(),
            thread_count: 0.into(),
            name: name_ptr.into(),
            cwd: cwd_ptr.into(),
        }
    }

    pub fn with_predefined_page_roots(pageaddr_phys: usize, name: &str, cwd: &str) -> Self {
        let name_ptr = CString::new(name).unwrap().into_raw();
        let cwd_ptr = CString::new(cwd).unwrap().into_raw();

        Self {
            id: next_pid(),
            address_space: AddressSpace::predefined(pageaddr_phys).into(),
            thread_count: 0.into(),
            name: name_ptr.into(),
            cwd: cwd_ptr.into(),
        }
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        unsafe {
            qemu_log!("PROCESS DEALLOCATED!");

            drop(CString::from_raw(
                self.name.load(core::sync::atomic::Ordering::Relaxed),
            ));
            drop(CString::from_raw(
                self.cwd.load(core::sync::atomic::Ordering::Relaxed),
            ));
        }
    }
}
