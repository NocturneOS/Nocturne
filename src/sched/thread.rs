use core::{cell::Cell, sync::atomic::AtomicPtr};

use alloc::sync::Arc;
use bitflags::bitflags;

use crate::{arch::CPURegisters, qemu_log, sched::{archspec::ArchitectureSpecificRegion, process::Process}};

bitflags! {
    #[derive(Copy, Clone, PartialEq, Eq)]
    #[repr(C)]
    pub struct ThreadFlags : usize {
        const User = 1 << 0;
        const Raw = 1 << 1;
    }
}

#[repr(C)]
#[derive(Copy, Clone, PartialEq, Eq)]
pub enum ThreadState {
    Ready,
    Running,
    Sleeping,
    Waiting,
    Paused,
    Dead
}

#[repr(C)]
pub struct Thread {
    pub id: usize,

    pub(crate) process: super::SharedProcess,
    pub flags: ThreadFlags,
    pub state: Cell<ThreadState>,

    pub stack_addr: usize,
    pub stack_size: usize,

    pub stack_pointer: usize,

    pub entry_point: usize,

    pub arch_specific_region: ArchitectureSpecificRegion,

    pub last_error: usize
}

unsafe impl Sync for Thread {}
unsafe impl Send for Thread {}

// impl Drop for Thread {
//     fn drop(&mut self) {
//         qemu_log!("Thread is dropped!");
//     }
// }
