#![no_std]

pub mod error;

pub type Result<T> = core::result::Result<T, error::Error>;

pub trait Read {
    fn read(&mut self, buffer: &mut [u8]) -> Result<u64>;
}

pub trait Write {
    fn write(&mut self, buffer: &[u8]) -> Result<u64>;
    fn flush(&mut self) -> Result<()>;
}

#[derive(Debug, Clone, Copy)]
pub enum SeekOffset {
    Beginning(u64),
    Current(i64),
    End(i64),
}

pub trait Seek {
    fn seek(&mut self, pos: SeekOffset) -> Result<u64>;

    fn rewind(&mut self) -> Result<()> {
        self.seek(SeekOffset::Beginning(0))?;

        Ok(())
    }

    fn position(&mut self) -> Result<u64> {
        self.seek(SeekOffset::Current(0))
    }
}