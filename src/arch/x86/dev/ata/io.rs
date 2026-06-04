use crate::arch::x86::dev::ata::error::ATAIOResult;

pub trait ATAIO {
    fn read(&mut self, lba: u64, output: &mut [u8]) -> ATAIOResult<()>;
    fn write(&mut self, lba: u64, input: &[u8]) -> ATAIOResult<()>;
}
