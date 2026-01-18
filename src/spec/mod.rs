pub mod units;

pub const WORD_SIZE: usize = core::mem::size_of::<usize>();
pub const WORD_SIZE_BITS: usize = WORD_SIZE * 8;
pub const KERNEL_BASE: usize = 0xC000_0000;
