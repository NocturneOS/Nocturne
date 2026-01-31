use alloc::sync::Arc;
use bitflags::bitflags;

use crate::{arch::CPURegisters, sched::{archspec::ArchitectureSpecificRegion, process::Process}};

bitflags! {
    #[derive(Copy, Clone, PartialEq, Eq)]
    pub struct ThreadFlags : usize {
        const User = 1 << 0;
        const Raw = 1 << 1;
    }
}

#[repr(C)]
pub enum ThreadState {
    Ready,
    Running,
    Sleeping,
    Waiting,
    Paused,
    Dead
}

#[repr(C, packed(4))]
pub struct Thread {
    pub id: usize,

    pub(crate) process: Arc<Process>,
    pub flags: ThreadFlags,
    pub state: ThreadState,

    pub stack_addr: usize,
    pub stack_size: usize,

    pub stack_pointer: usize,

    pub entry_point: usize,

    pub arch_specific_region: ArchitectureSpecificRegion,

    pub last_error: usize
}