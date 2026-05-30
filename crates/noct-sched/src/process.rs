use core::{
    ffi::c_char,
    sync::atomic::{AtomicPtr, AtomicUsize, Ordering},
};

use alloc::ffi::CString;
use lazy_static::lazy_static;
use noct_elf::ProgramImage;
use noct_sync::pseudosync::PseudoSync;

use crate::qemu_log;

use noct_mem::{addrspace_manager::AddressSpace, paging::GlobalPagingArchitecture};

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

    pub program_image: Option<PseudoSync<ProgramImage>>,
}

#[cfg(target_arch = "x86")]
const _: &[()] = &[
    assert!(core::mem::offset_of!(Process, id) == 0),
    assert!(core::mem::offset_of!(Process, address_space) == 4),
];

fn next_pid() -> usize {
    GLOBAL_PID.fetch_add(1, Ordering::Release)
}

impl Process {
    pub fn new(name: &str, cwd: &str) -> Self {
        let name_ptr = CString::new(name).unwrap().into_raw();
        let cwd_ptr = CString::new(cwd).unwrap().into_raw();

        let address_space = AddressSpace::<GlobalPagingArchitecture>::new();

        Self {
            id: next_pid(),
            address_space: address_space.into(),
            thread_count: 0.into(),
            name: name_ptr.into(),
            cwd: cwd_ptr.into(),
            program_image: Some(ProgramImage::new().into()),
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
            program_image: None
        }
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        unsafe {
            qemu_log!("PROCESS #{} DEALLOCATED!", self.id);

            drop(CString::from_raw(
                self.name.load(core::sync::atomic::Ordering::Relaxed),
            ));
            drop(CString::from_raw(
                self.cwd.load(core::sync::atomic::Ordering::Relaxed),
            ));
        }
    }
}
