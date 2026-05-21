#![no_std]

extern crate alloc;

use alloc::{boxed::Box};

use noct_logger::qemu_log;

use crate::{error::FilesystemResult, handles::{directory::{DirectoryHandle, DirectoryEntry}, file::{FileHandle, FileOpenMode, SeekOffset}}};

pub mod error;
pub mod debugfs;
pub mod entity;
pub mod handles;
pub mod mount;
pub mod nullfs;
pub mod store;

/// Alternative to Unix's inode.
pub type NodeId = u64;

pub trait Filesystem: Sync + Send {
	fn probe(&self, disk_id: &str) -> Option<Box<dyn FilesystemInstance>>;
	fn name(&self) -> &str;
}

pub trait FilesystemInstance: Sync + Send {
	fn fs(&self) -> &dyn Filesystem;

	fn open(&self, path: &str, mode: FileOpenMode) -> FilesystemResult<FileHandle>;

	fn read(&self, handle: &mut FileHandle, buffer: &mut [u8]) -> FilesystemResult<u64>;
	fn write(&self, handle: &mut FileHandle, buffer: &[u8]) -> FilesystemResult<u64>;

	fn opendir(&self, path: &str) -> FilesystemResult<DirectoryHandle>;
	fn readdir(&self, handle: &mut DirectoryHandle) -> FilesystemResult<DirectoryEntry>;

	fn info(&self, path: &str) -> FilesystemResult<crate::entity::EntityInfo>;

	fn close(&self, handle: &mut FileHandle) -> FilesystemResult<()>;
	fn closedir(&self, handle: &mut DirectoryHandle) -> FilesystemResult<()>;

	fn mkfile(&self, path: &str) -> FilesystemResult<()>;
	fn mkdir(&self, path: &str) -> FilesystemResult<()>;

	fn remove(&self, path: &str) -> FilesystemResult<()>;
}

pub fn probe() {
	qemu_log!("FSMan: {} filesystems registered.", crate::store::STORE.lock().len());

	for fs in crate::store::STORE.lock().iter() {
		qemu_log!(" - {}", fs.name());
	}

	mount::scan_and_mount();
}
