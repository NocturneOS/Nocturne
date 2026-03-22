#![no_std]

pub mod units;

pub const WORD_SIZE: usize = core::mem::size_of::<usize>();
pub const WORD_SIZE_BITS: usize = WORD_SIZE * 8;

#[cfg(target_arch = "x86_64")]
pub const KERNEL_BASE: usize = 0xFFFFFFFF_80000000;

#[cfg(target_arch = "x86")]
pub const KERNEL_BASE: usize = 0xC000_0000;
