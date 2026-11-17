//! Buffer Descriptor List (BDL) entry layout used by the AC'97 bus master.

/// Interrupt on completion.
pub const BDL_FLAG_IOC: u16 = 1 << 15;

/// Buffer underrun policy.
pub const BDL_FLAG_BUP: u16 = 1 << 14;

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct Bdl {
    memory_pos: u32,
    sample_count: u16,
    flags: u16,
}

impl Bdl {
    pub const fn new(memory_pos: u32, sample_count: u16, flags: u16) -> Self {
        Self {
            memory_pos,
            sample_count,
            flags,
        }
    }

    pub const fn memory_pos(&self) -> u32 {
        self.memory_pos
    }

    pub const fn sample_count(&self) -> u16 {
        self.sample_count
    }
}
