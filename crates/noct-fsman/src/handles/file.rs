use alloc::{string::String, sync::Arc};
use bitflags::bitflags;

use crate::{
    entity::EntityInfo, error::{FilesystemError, FilesystemResult}
};

bitflags! {
    #[derive(Debug, Clone, Copy)]
    pub struct FileOpenMode: u32 {
        const Read = 1 << 0;
        const Write = 1 << 1;
        const Truncate = 1 << 2;
    }
}

#[derive(Debug, Clone, Copy)]
pub enum SeekOffset {
    Beginning(u64),
    Current(u64),
    End(u64),
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

    pub fn read(&mut self, buffer: &mut [u8]) -> FilesystemResult<u64> {
        let fs =
            crate::mount::get_handle(&self.disk_id).ok_or(FilesystemError::DiskNotRecognized)?;

        fs.read(self, buffer)
    }

    pub fn write(&mut self, buffer: &[u8]) -> FilesystemResult<u64> {
        let fs =
            crate::mount::get_handle(&self.disk_id).ok_or(FilesystemError::DiskNotRecognized)?;

        fs.write(self, buffer)
    }

    pub fn seek(&mut self, offset: SeekOffset) -> FilesystemResult<u64> {
        self.position = match offset {
			SeekOffset::Beginning(pos) => pos,
			SeekOffset::Current(pos) => {
				if self.position + pos > self.file_info.size {
					return Err(FilesystemError::InvalidSeek);
				}

				self.position + pos
			},
			SeekOffset::End(pos) => {
				if pos > self.file_info.size {
					return Err(FilesystemError::InvalidSeek);
				}

				self.file_info.size - pos
			}
		};

		Ok(self.position)
    }

	pub fn tell(&mut self) -> FilesystemResult<u64> {
		Ok(self.position)
	}
}

impl Drop for FileHandle {
    fn drop(&mut self) {
        let Some(fs) =
            crate::mount::get_handle(&self.disk_id) else {
                return
            };

        fs.close(self).ok();
    }
}