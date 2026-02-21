use core::{cell::Cell, sync::atomic::{AtomicPtr, AtomicUsize}};

use bitflags::bitflags;

use crate::sched::archspec::ArchitectureSpecificRegion;

bitflags! {
    #[derive(Copy, Clone, PartialEq, Eq)]
    #[repr(C)]
    pub struct ThreadFlags : usize {
        const User = 1 << 0;
        const Raw = 1 << 1;
    }
}

#[repr(usize)]
#[derive(Copy, Clone, PartialEq, Eq)]
pub enum ThreadState {
    Ready,
    Running,
    Sleeping,
    Waiting,
    Paused,
    Dead
}

impl From<usize> for ThreadState {
    fn from(value: usize) -> Self {
        match value {
            0 => ThreadState::Ready,
            1 => ThreadState::Running,
            2 => ThreadState::Sleeping,
            3 => ThreadState::Waiting,
            4 => ThreadState::Paused,
            5 => ThreadState::Dead,
            _ => panic!("Conversion from `usize` to `ThreadState` failed! (value was: {})", value)
        }
    }
}

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub enum ThreadPriority {
    High,
    #[default]
    Medium,
    Low
}

impl ThreadPriority {
    pub fn to_ticks(&self) -> usize {
        match self {
            Self::High => 10,
            Self::Medium => 5,
            Self::Low => 1,
        }
    }
}

#[repr(C)]
pub struct Thread {
    pub id: usize,

    pub(crate) process: super::SharedProcess,
    pub flags: ThreadFlags,
    pub state: AtomicUsize,

    pub stack_addr: usize,
    pub stack_size: usize,

    pub stack_pointer: usize,

    pub entry_point: usize,

    pub arch_specific_region: ArchitectureSpecificRegion,

    // SAFE ZONE: Add or remove fields here, it won't change the scheduler behaviour.

    pub last_error: AtomicUsize,

    pub priority: ThreadPriority,
    pub time_quantum: AtomicUsize
}

// Assert that offsets are valid for our assembly code.
#[cfg(target_arch = "x86")]
const _: &[()] = &[
    assert!(core::mem::offset_of!(Thread, id) == 0),
    assert!(core::mem::offset_of!(Thread, process) == 4),
    assert!(core::mem::offset_of!(Thread, flags) == 8),
    assert!(core::mem::offset_of!(Thread, state) == 12),
    assert!(core::mem::offset_of!(Thread, stack_addr) == 16),
    assert!(core::mem::offset_of!(Thread, stack_size) == 20),
    assert!(core::mem::offset_of!(Thread, stack_pointer) == 24),
];

#[cfg(target_arch = "x86_64")]
const _: &[()] = &[
    assert!(core::mem::offset_of!(Thread, id) == 0),
    assert!(core::mem::offset_of!(Thread, process) == 0x8),
    assert!(core::mem::offset_of!(Thread, flags) == 0x10),
    assert!(core::mem::offset_of!(Thread, state) == 0x18),
    assert!(core::mem::offset_of!(Thread, stack_addr) == 0x20),
    assert!(core::mem::offset_of!(Thread, stack_size) == 0x28),
    assert!(core::mem::offset_of!(Thread, stack_pointer) == 0x30),
    assert!(core::mem::offset_of!(Thread, arch_specific_region) == 0x40),
];

// impl Drop for Thread {
//     fn drop(&mut self) {
//         qemu_log!("Thread is dropped!");
//     }
// }
