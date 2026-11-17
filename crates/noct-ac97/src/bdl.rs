#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct Bdl {
    memory_pos: u32,
    sample_count: u16,
    flags: u16
}