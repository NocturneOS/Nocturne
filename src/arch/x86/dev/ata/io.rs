use crate::arch::x86::dev::ata::error::ATAIOResult;

pub trait ATAIO {
    fn read48(&mut self, lba: u64, output: &mut [u8]) -> ATAIOResult<()>;
    fn write48(&mut self, lba: u64, input: &[u8]) -> ATAIOResult<()>;
}