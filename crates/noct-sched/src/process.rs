use core::{
    ffi::{CStr, c_char},
    sync::atomic::{
        AtomicPtr, AtomicU32, AtomicUsize,
        Ordering,
    },
};

use alloc::{borrow::Cow, ffi::CString, sync::Arc};
use lazy_static::lazy_static;
use noct_elf::ProgramImage;
use noct_sync::pseudosync::PseudoSync;
use spin::Mutex;

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
    pub parent_pid: usize,  // it is updated only on creation, so no synchronization needed there
    pub thread_count: AtomicUsize,
    pub name: AtomicPtr<c_char>,
    pub cwd: AtomicPtr<c_char>,

    pub program_image: Option<PseudoSync<ProgramImage>>,
    pub handle: Option<Arc<ProcessHandle>>,

    pub resources: Mutex<noct_descriptor::Descriptors>,

    // Heap goes there. Every `Heap`'s method should accept address_space as a parameter, so that it can be used in the context of the process.
    pub heap: Mutex<Option<noct_mem::external_heap::Heap<GlobalPagingArchitecture>>>,
}

pub struct ProcessHandle {
    pub pid: usize,
    pub exit_code: AtomicU32,
}

impl ProcessHandle {
    pub fn new(pid: usize) -> Self {
        Self {
            pid,
            exit_code: Default::default(),
        }
    }

    pub fn wait(&self) -> Option<u32> {
        Some(crate::waitpid(self))
    }
}

/// Used for tracking process states (dead or not).
///
/// Those states are used to implement [`crate::waitpid`]
pub struct ProcessEntry {
    handle: Arc<ProcessHandle>,
    state: ProcessState
}

#[derive(Copy, Clone, PartialEq)]
pub enum ProcessState {
    Alive,
    Zombie
}

impl ProcessEntry {
    pub fn alive(hdl: Arc<ProcessHandle>) -> Self {
        Self {
            handle: hdl,
            state: ProcessState::Alive
        }
    }

    pub fn handle(&self) -> &Arc<ProcessHandle> {
        &self.handle
    }

    pub fn state(&self) -> ProcessState {
        self.state
    }

    pub fn set_state(&mut self, state: ProcessState) {
        self.state = state;
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
    pub fn new(parent_pid: usize, name: &str, cwd: &str) -> Self {
        let name_ptr = CString::new(name).unwrap().into_raw();
        let cwd_ptr = CString::new(cwd).unwrap().into_raw();

        let address_space = AddressSpace::<GlobalPagingArchitecture>::new();

        let pid = next_pid();

        let descriptors = noct_descriptor::Descriptors::new();

        Self {
            id: pid,
            address_space: address_space.into(),
            thread_count: 0.into(),
            name: name_ptr.into(),
            cwd: cwd_ptr.into(),
            program_image: Some(ProgramImage::new().into()),
            handle: Some(ProcessHandle::new(pid).into()),
            resources: descriptors.into(),
            parent_pid,
            heap: None.into(), // heap will be initialized after the program image is loaded and the heap region is determined
        }
    }

    /// This method is used only for kernel process initialization.
    pub fn with_predefined_page_roots(pageaddr_phys: usize, name: &str, cwd: &str) -> Self {
        let name_ptr = CString::new(name).unwrap().into_raw();
        let cwd_ptr = CString::new(cwd).unwrap().into_raw();

        let descriptors = noct_descriptor::Descriptors::new();

        Self {
            id: next_pid(),
            address_space: AddressSpace::predefined(pageaddr_phys).into(),
            thread_count: 0.into(),
            name: name_ptr.into(),
            cwd: cwd_ptr.into(),
            program_image: None,
            handle: None,
            resources: descriptors.into(),
            heap: None.into(), // this method is only used on kernel initialization, heap is managed externally.
            parent_pid: 0,
        }
    }

    pub fn into_handle_ref(&self) -> Arc<ProcessHandle> {
        Arc::clone(self.handle.as_ref().expect("Cannot call `Process::into_handle` on kernel process image!"))
    }

    pub fn into_handle(this: Arc<Self>) -> Arc<ProcessHandle> {
        Arc::clone(
            this.handle
                .as_ref()
                .expect("Cannot call `Process::into_handle` on kernel process image!"),
        )
    }

    pub fn recalculate_heap(&self) {
        if let Some(program_image) = &self.program_image {
            let program_image = program_image.get();

            for i in program_image.loaded_segments.iter() {
                qemu_log!("{i:x?}");
            }

            let heap_base = program_image
                .loaded_segments
                .iter()
                .map(|seg| seg.virtual_addr + seg.page_count * noct_mem::get_page_size())
                .max()
                .expect("Failed to determine heap bounds! (No program sections?)");

            let heap_max = heap_base + (128 << 20); // 128 MiB heap limit for now, can be adjusted later.

            qemu_log!(
                "Process #{}: Heap recalculated: base = {heap_base:#x}, max = {heap_max:#x}",
                self.id
            );

            *self.heap.lock() = Some(noct_mem::external_heap::Heap::new(heap_base, heap_max))
        }
    }

    pub fn cwd(&self) -> Cow<'_, str> {
        unsafe { CStr::from_ptr(self.cwd.load(Ordering::Acquire)).to_string_lossy() }
    }

    pub fn chdir(&self, new_path: &str) {
        let cwd_ptr = CString::new(new_path).unwrap();

        drop(unsafe { CString::from_raw(self.cwd.load(core::sync::atomic::Ordering::Relaxed)) });

        self.cwd.store(cwd_ptr.into_raw(), Ordering::Release);
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        unsafe {
            drop(CString::from_raw(
                self.name.load(core::sync::atomic::Ordering::Relaxed),
            ));
            drop(CString::from_raw(
                self.cwd.load(core::sync::atomic::Ordering::Relaxed),
            ));

            qemu_log!("PROCESS #{} DEALLOCATED!", self.id);
        }
    }
}
