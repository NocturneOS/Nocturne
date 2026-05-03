#![no_std]

extern crate alloc;

use alloc::boxed::Box;
use lazy_static::lazy_static;

use bitflags::bitflags;

use crate::error::FilesystemResult;

pub mod error;

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

/// A file handle. It is an opaque type that represents an open file.
/// The actual implementation of the file handle is hidden from the user of the API, ...
/// ... and it can be implemented in various ways depending on the underlying filesystem.
/// 
/// The file handle is used to perform operations on the open file, ...
/// ... such as reading, writing, seeking, etc.
pub struct FileHandle {
	node_id: NodeId,
	position: u64,
}

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

pub trait Filesystem {
	fn probe(&self, disk_id: &str) -> Option<Box<dyn FilesystemInstance>>;
}


pub trait FilesystemInstance {
	fn open(&mut self, disk_id: &str, path: &str, mode: FileOpenMode) -> FilesystemResult<()>;
	fn opendir(&mut self, disk_id: &str, path: &str) -> FilesystemResult<()>;

	fn read(&mut self, handle: &mut FileHandle, buffer: &mut [u8]) -> FilesystemResult<u64>;
	fn write(&mut self, handle: &mut FileHandle, buffer: &[u8]) -> FilesystemResult<u64>;
	
	/// Seeks to a new position in the file, returning the new position from the beginning of the file.
	fn seek(&mut self, handle: &mut FileHandle, offset: SeekOffset) -> FilesystemResult<u64>;
	fn tell(&mut self, handle: &mut FileHandle) -> FilesystemResult<u64> {
		self.seek(handle, SeekOffset::Current(0))
	}
}
