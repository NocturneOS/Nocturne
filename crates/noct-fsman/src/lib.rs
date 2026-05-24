#![no_std]

extern crate alloc;

use alloc::boxed::Box;

use noct_logger::qemu_log;

use crate::{
    handles::{
        directory::{DirectoryEntry, DirectoryHandle},
        file::{FileHandle, FileOpenMode},
    },
};

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

    fn open(&self, path: &str, mode: FileOpenMode) -> noct_io::Result<FileHandle>;

    fn read(&self, handle: &mut FileHandle, buffer: &mut [u8]) -> noct_io::Result<u64>;
    fn write(&self, handle: &mut FileHandle, buffer: &[u8]) -> noct_io::Result<u64>;

    fn opendir(&self, path: &str) -> noct_io::Result<DirectoryHandle>;
    fn readdir(&self, handle: &mut DirectoryHandle) -> noct_io::Result<DirectoryEntry>;

    fn info(&self, path: &str) -> noct_io::Result<crate::entity::EntityInfo>;

    fn close(&self, handle: &mut FileHandle) -> noct_io::Result<()>;
    fn closedir(&self, handle: &mut DirectoryHandle) -> noct_io::Result<()>;

    fn mkfile(&self, path: &str) -> noct_io::Result<()>;
    fn mkdir(&self, path: &str) -> noct_io::Result<()>;

    fn remove(&self, path: &str) -> noct_io::Result<()>;
}

pub fn probe() {
    qemu_log!(
        "FSMan: {} filesystems registered.",
        crate::store::STORE.lock().len()
    );

    for fs in crate::store::STORE.lock().iter() {
        qemu_log!(" - {}", fs.name());
    }

    mount::scan_and_mount();
}
