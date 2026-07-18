use alloc::{string::String, sync::Arc};
use bitflags::bitflags;
use noct_io::{Read, Seek, SeekOffset, Write, error::Error};

use crate::{
    entity::EntityInfo,
};

bitflags! {
    #[derive(Debug, Clone, Copy)]
    pub struct FileOpenMode: u32 {
        const Read = 1 << 0;
        const Write = 1 << 1;
        const Create = 1 << 2;
        const Append = 1 << 3;
        const Truncate = 1 << 4;
    }
}

/// A file handle. It is an opaque type that represents an open file.
/// The actual implementation of the file handle is hidden from the user of the API, ...
/// ... and it can be implemented in various ways depending on the underlying filesystem.
///
/// The file handle is used to perform operations on the open file, ...
/// ... such as reading, writing, seeking, etc.
#[derive(Debug)]
pub struct FileHandle {
    // XXX: This could be done better, without looking up for a disk ID on each operation.
    // XXX: Like `fh: u64` (file handle)? File handles are handled by filesysten instance.
    // XXX: Filesystem instance will have a map of file handles to actual file information (like position, node ID, etc.) inside?
    pub file_handle: u64,

    disk_id: Arc<String>,

    file_info: EntityInfo,

    pub position: u64,
}

impl FileHandle {
    pub fn new(file_handle: u64, disk_id: Arc<String>, file_info: EntityInfo) -> Self {
        Self {
            file_handle,
            disk_id,
            file_info,
            position: 0,
        }
    }
}

impl Read for FileHandle {
    fn read(&mut self, buffer: &mut [u8]) -> noct_io::Result<u64> {
        let fs =
            crate::mount::get_handle(&self.disk_id).ok_or(Error::FilesystemNotRecognized)?;

        fs.read(self, buffer)
    }
}

impl Write for FileHandle {
    fn write(&mut self, buffer: &[u8]) -> noct_io::Result<u64> {
        let fs =
            crate::mount::get_handle(&self.disk_id).ok_or(Error::FilesystemNotRecognized)?;

        fs.write(self, buffer)
    }

    fn flush(&mut self) -> noct_io::Result<()> {
        Ok(())
    }
}

impl Seek for FileHandle {
    fn seek(&mut self, offset: SeekOffset) -> noct_io::Result<u64> {
        self.position = match offset {
            SeekOffset::Beginning(pos) => pos,
            SeekOffset::Current(pos) => {
                let new_position = self
                    .position
                    .checked_add_signed(pos)
                    .ok_or(Error::InvalidSeek)?;

                if new_position > self.file_info.size {
                    return Err(Error::InvalidSeek);
                }

                new_position
            }
            SeekOffset::End(pos) => {
                if pos > self.file_info.size as i64 {
                    return Err(Error::InvalidSeek);
                }

                self.file_info
                    .size
                    .checked_sub_signed(pos)
                    .ok_or(Error::InvalidSeek)?
            }
        };

        Ok(self.position)
    }

    fn position(&mut self) -> noct_io::Result<u64> {
        Ok(self.position)
    }
}

impl Drop for FileHandle {
    fn drop(&mut self) {
        let Some(fs) = crate::mount::get_handle(&self.disk_id) else {
            return;
        };

        fs.close(self).ok();
    }
}
