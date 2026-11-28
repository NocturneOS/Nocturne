#![no_std]

use core::{
    alloc::Layout,
    ops::{Deref, DerefMut},
};

use alloc::{boxed::Box, string::String, vec};
use noct_diskman::{
    error::{DiskManError, DiskManResult},
    structures::{Command, DriveType},
};
use noct_mem::paging::PageFlags;

extern crate alloc;

pub enum MemoryDiskSource {
    Predefined {
        physical: usize,
        buffer: &'static mut [u8],
        layout: Layout
    },
    Allocated(Box<[u8]>),
}

impl Deref for MemoryDiskSource {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Predefined { buffer, .. } => buffer,
            Self::Allocated(items) => items,
        }
    }
}

impl DerefMut for MemoryDiskSource {
    fn deref_mut(&mut self) -> &mut Self::Target {
        match self {
            Self::Predefined { buffer, .. } => buffer,
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

    pub fn raw_physical(phys_addr: usize, size: usize) -> Self {
        // Align size too.
        let aligned_size = size.next_multiple_of(0x1000);
        let layout = Layout::from_size_align(aligned_size, 0x1000).unwrap();

        let virt = unsafe {
            noct_mem::heap::allocate_no_map(layout)
        };

        assert!(!virt.is_null());

        noct_mem::paging::map_pages(
            phys_addr,
            virt.addr(),
            aligned_size,
            PageFlags::Present,
        );

        Self {
            diskman_id: noct_diskman::generate_new_id("mem"),
            data: MemoryDiskSource::Predefined {
                physical: phys_addr,
                buffer: unsafe { core::slice::from_raw_parts_mut(virt, size) },
                layout
            },
        }
    }

    pub fn raw_virtual(virt_addr: usize, size: usize) -> Self {
        assert!(virt_addr > 0);

        Self {
            diskman_id: noct_diskman::generate_new_id("mem"),
            data: MemoryDiskSource::Predefined {
                physical: virt_addr,
                buffer: unsafe { core::slice::from_raw_parts_mut(virt_addr as *mut u8, size) },
                layout: unsafe { Layout::from_size_align_unchecked(size, 1) }
            },
        }
    }
}

impl Drop for MemoryDisk {
    fn drop(&mut self) {
        if let MemoryDiskSource::Predefined { buffer, layout, .. } = &mut self.data {
            unsafe { alloc::alloc::dealloc(buffer.as_mut_ptr(), *layout) };
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

    fn block_size(&self) -> Option<usize> {
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

        buffer.copy_from_slice(
            self.data
                .get(range)
                .ok_or(DiskManError::LocationOutOfBounds)?,
        );

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
