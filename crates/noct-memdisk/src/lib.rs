#![no_std]

use alloc::{boxed::Box, string::String};
use noct_diskman::{error::{DiskManError, DiskManResult}, structures::{Command, DriveType}};

extern crate alloc;

pub struct MemoryDisk {
    diskman_id: String,
    data: Box<[u8]>
}

impl noct_diskman::drive::Drive for MemoryDisk {
    fn get_name(&self) -> &str {
        "mem"
    }

    fn get_id(&self) -> &str {
        &self.diskman_id
    }

    fn drive_type(&self) -> DriveType {
        DriveType::HardDrive
    }

    fn capacity(&self) -> Option<u64> {
        Some(self.data.len() as u64)
    }

    fn block_size(&self) -> Option<u32> {
        Some(1)
    }

    fn buffer_address_alignment(&self) -> usize {
        16
    }

    fn read(&mut self, location: u64, buffer: &mut [u8]) -> DiskManResult<u64> {
        let read_size = core::cmp::min(
            self.data.len() as u64 - location,
            buffer.len() as u64
        );

        let range = location as usize..(location + read_size) as usize;

        self.data.get(range).ok_or(DiskManError::LocationOutOfBounds)?;

        Ok(read_size)
    }

    fn write(&mut self, location: u64, buffer: &[u8]) -> DiskManResult<u64> {
        let write_size = core::cmp::min(
            self.data.len() as u64 - location,
            buffer.len() as u64
        );

        let range = location as usize..(location + write_size) as usize;

        self.data.get_mut(range).ok_or(DiskManError::LocationOutOfBounds)?.copy_from_slice(buffer);

        Ok(write_size)
    }

    fn control(&mut self, _command: Command, _command_parameters: &[u8], _data: &mut [u8]) -> DiskManResult<()> {
        Err(DiskManError::UnsupportedOperation)
    }
}