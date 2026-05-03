#![no_std]

use bitflags::bitflags;

/// Filesystem entity type.
#[derive(Debug, Clone, Copy)]
pub enum EntityType {
	Directory,
	File,
	// Symlinks, hardlinks and FIFO nodes are not currently planned to support.
	// I'll add them as I make support from filesystems' side and ...
	// ... some API endpoints.
}

/// Alternative to Unix's inode.
pub type NodeId = u64;

pub struct FileHandle;
pub struct DirectoryHandle;

bitflags! {
	#[derive(Clone, Copy)]
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
	End(u64)
}

#[derive(Debug, Clone, Copy)]
pub enum FilesystemError {
	
}

type FilesystemResult<T> = Result<T, FilesystemError>;

pub trait Filesystem {
	fn open(&mut self, disk_id: &str, path: &str, mode: FileOpenMode) -> FilesystemResult<()>;
	fn opendir(&mut self, disk_id: &str, path: &str) -> FilesystemResult<()>;

	fn read(&mut self, handle: &mut FileHandle, buffer: &mut [u8]) -> FilesystemResult<u64>;
	fn write(&mut self, handle: &mut FileHandle, buffer: &[u8]) -> FilesystemResult<u64>;
	
	fn seek(&mut self, handle: &mut FileHandle, offset: SeekOffset) -> FilesystemResult<u64>;
	fn tell(&mut self, handle: &mut FileHandle) -> FilesystemResult<u64> {
		self.seek(handle, SeekOffset::Current(0))
	}
}
