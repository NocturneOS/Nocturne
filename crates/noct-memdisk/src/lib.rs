#![no_std]

use core::{
    borrow::Borrow,
    ops::{Deref, DerefMut},
};

use alloc::{boxed::Box, string::String, vec};
use noct_diskman::{
    error::{DiskManError, DiskManResult},
    structures::{Command, DriveType},
};

extern crate alloc;

pub enum MemoryDiskSource {
    Predefined(&'static mut [u8]),
    Allocated(Box<[u8]>),
}

impl Deref for MemoryDiskSource {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Predefined(items) => items,
            Self::Allocated(items) => &items,
        }
    }
}

impl DerefMut for MemoryDiskSource {
    fn deref_mut(&mut self) -> &mut Self::Target {
        match self {
            Self::Predefined(items) => items,
            Self::Allocated(items) => items.as_mut(),
        }
    }
}

pub struct MemoryDisk {
    diskman_id: String,
    data: MemoryDiskSource,
}

impl MemoryDisk {
    pub fn alloc(size: usize) -> Self {
        Self {
            diskman_id: noct_diskman::generate_new_id("mem"),
            data: MemoryDiskSource::Allocated(vec![0u8; size].into_boxed_slice()),
        }
    }

    pub fn raw(ptr: *mut u8, size: usize) -> Self {
        Self {
            diskman_id: noct_diskman::generate_new_id("mem"),
            data: MemoryDiskSource::Predefined(unsafe {
                core::slice::from_raw_parts_mut(ptr, size)
            }),
        }
    }
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
        if location > self.data.len() as u64 {
            return Err(DiskManError::LocationOutOfBounds);
        }

        let read_size = core::cmp::min(self.data.len() as u64 - location, buffer.len() as u64);

        let range = location as usize..(location + read_size) as usize;

        self.data
            .get(range)
            .ok_or(DiskManError::LocationOutOfBounds)?;

        Ok(read_size)
    }

    fn write(&mut self, location: u64, buffer: &[u8]) -> DiskManResult<u64> {
        let write_size = core::cmp::min(self.data.len() as u64 - location, buffer.len() as u64);

        let range = location as usize..(location + write_size) as usize;

        self.data
            .get_mut(range)
            .ok_or(DiskManError::LocationOutOfBounds)?
            .copy_from_slice(buffer);

        Ok(write_size)
    }

    fn control(
        &mut self,
        _command: Command,
        _command_parameters: &[u8],
        _data: &mut [u8],
    ) -> DiskManResult<()> {
        Err(DiskManError::UnsupportedOperation)
    }
}
