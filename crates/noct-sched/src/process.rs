use core::{
    ffi::c_char,
    sync::atomic::{AtomicPtr, AtomicU32, AtomicUsize, Ordering},
};

use alloc::{ffi::CString, sync::Arc};
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
    pub handle: Option<Arc<ProcessHandle>>
}

pub struct ProcessHandle {
    pub pid: usize,
    pub exit_code: AtomicU32,
}

impl ProcessHandle {
    pub fn new(pid: usize) -> Self {
        Self {
            pid,
            exit_code: Default::default()
        }
    }

    pub fn wait(&self) -> Option<u32> {
        crate::waitpid(self)
    }
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

        let pid = next_pid();

        Self {
            id: pid,
            address_space: address_space.into(),
            thread_count: 0.into(),
            name: name_ptr.into(),
            cwd: cwd_ptr.into(),
            program_image: Some(ProgramImage::new().into()),
            handle: Some(ProcessHandle::new(pid).into())
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
            program_image: None,
            handle: None
        }
    }

    pub fn into_handle(this: Arc<Self>) -> Arc<ProcessHandle> {
        Arc::clone(this.handle.as_ref().expect("Cannot call `Process::into_handle` on kernel process image!"))
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
