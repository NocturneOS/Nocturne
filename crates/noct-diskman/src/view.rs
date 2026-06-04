use core::alloc::Layout;

/// A "view" of a block device that allows reading/writing bytes at arbitrary offsets, abstracting away block boundaries.
/// This is used by higher-level components that want to work with byte offsets rather than block numbers.
use crate::{drive::Drive, error::DiskManResult};

pub struct DiskView<'a> {
    drive: &'a mut dyn Drive,
    block_size: usize,
}

impl<'a> DiskView<'a> {
    pub fn new(drive: &'a mut dyn Drive) -> Self {
        let block_size = drive.block_size().unwrap_or(512);

        Self { drive, block_size }
    }

    pub fn read_bytes(&mut self, byte_offset: u64, buf: &mut [u8]) -> DiskManResult<i64> {
        if buf.is_empty() {
            return Ok(0);
        }

        let bs = self.block_size as u64;
        let start_lba = byte_offset / bs;
        let end_lba = (byte_offset + buf.len() as u64 + bs - 1) / bs;
        let num_blocks = end_lba - start_lba;

        let buf_align = self.drive.buffer_address_alignment();
        let layout = Layout::from_size_align((num_blocks * bs) as _, buf_align).unwrap();

        let buffer = unsafe { alloc::alloc::alloc(layout) } as *mut u8;

        if buffer.is_null() {
            alloc::alloc::handle_alloc_error(layout);
        }

        let read_result = self.drive.read(start_lba, unsafe {
            core::slice::from_raw_parts_mut(buffer, (num_blocks * bs) as usize)
        });

        if let Err(e) = read_result {
            unsafe { alloc::alloc::dealloc(buffer, layout) };
            return Err(e);
        }

        // Copy relevant slice into output buffer.
        let offset_within_first_block = (byte_offset % bs) as usize;
        let bytes_to_copy = buf.len();

        unsafe {
            core::ptr::copy_nonoverlapping(
                buffer.add(offset_within_first_block),
                buf.as_mut_ptr(),
                bytes_to_copy,
            );
        }

        unsafe { alloc::alloc::dealloc(buffer, layout) };

        Ok(bytes_to_copy as i64)
    }

    pub fn write_bytes(&mut self, byte_offset: u64, buf: &[u8]) -> DiskManResult<i64> {
        if buf.is_empty() {
            return Ok(0);
        }

        let bs = self.block_size as u64;
        let start_lba = byte_offset / bs;
        let end_lba = (byte_offset + buf.len() as u64 + bs - 1) / bs;
        let num_blocks = end_lba - start_lba;

        let buf_align = self.drive.buffer_address_alignment();
        let layout = Layout::from_size_align((num_blocks * bs) as _, buf_align).unwrap();

        let buffer = unsafe { alloc::alloc::alloc(layout) } as *mut u8;

        if buffer.is_null() {
            alloc::alloc::handle_alloc_error(layout);
        }

        // If the write is not block-aligned, we need to read the first and/or last block to preserve the unaffected bytes.
        if byte_offset % bs != 0 || (byte_offset + buf.len() as u64) % bs != 0 {
            self.drive.read(start_lba, unsafe {
                core::slice::from_raw_parts_mut(buffer, (num_blocks * bs) as usize)
            })?;
        }

        // Copy input buffer into the correct position within the block-aligned buffer.
        let offset_within_first_block = (byte_offset % bs) as usize;
        let bytes_to_copy = buf.len();
        unsafe {
            core::ptr::copy_nonoverlapping(
                buf.as_ptr(),
                buffer.add(offset_within_first_block),
                bytes_to_copy,
            );
        }

        let write_result = self.drive.write(start_lba, unsafe {
            core::slice::from_raw_parts(buffer, (num_blocks * bs) as usize)
        });

        unsafe { alloc::alloc::dealloc(buffer, layout) };

        if let Err(e) = write_result {
            return Err(e);
        }

        Ok(bytes_to_copy as i64)
    }
}
