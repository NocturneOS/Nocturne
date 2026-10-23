#![no_std]

pub mod units;

pub const WORD_SIZE: usize = core::mem::size_of::<usize>();
pub const WORD_SIZE_BITS: usize = WORD_SIZE * 8;

#[cfg(target_arch = "x86_64")]
pub const KERNEL_BASE: usize = 0xFFFF_FFFF_8000_0000;

#[cfg(target_arch = "x86")]
pub const KERNEL_BASE: usize = 0xC000_0000;

pub const USER_SPACE_TOP: usize = cfg_select! {
    target_arch = "x86_64" => { 0x0000_8000_0000_0000 },
    _ => KERNEL_BASE
};
