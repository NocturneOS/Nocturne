use alloc::{boxed::Box, string::{String, ToString}, sync::Arc};
use core::sync::atomic::AtomicUsize;
use noct_logger::qemu_log;
use noct_time::repr::Time;

use crate::{DirectoryHandle, FileHandle, FileOpenMode, Filesystem, FilesystemInstance, entity::{EntityInfo, EntityType}, error::{FilesystemError, FilesystemResult}};

pub struct DebugFilesystem;

impl Filesystem for DebugFilesystem {
    fn probe(&self, disk_id: &str) -> Option<Box<dyn FilesystemInstance>> {
        Some(Box::new(DebugFSInstance::new(disk_id)))
    }

    fn name(&self) -> &str {
        "debugfs"
    }
}

pub struct DebugFSInstance {
    disk_id: Arc<String>,

    id_arena: AtomicUsize,
}

impl DebugFSInstance {
    pub fn new(disk_id: &str) -> Self {
        Self {
            disk_id: disk_id.to_string().into(),
            id_arena: AtomicUsize::new(0),
        }
    }
}

impl FilesystemInstance for DebugFSInstance {
    fn fs(&self) -> &dyn Filesystem {
        &DebugFilesystem
    }

    fn open(&self, path: &str, mode: FileOpenMode) -> FilesystemResult<FileHandle> {
        qemu_log!("DebugFS: open called with path '{}' and mode {:?}", path, mode);

        let finfo = EntityInfo {
            node_id: 0,
            entity_type: EntityType::File,
            size: 0,
            created_at: Time::epoch(),
            modified_at: Time::epoch(),
        };

        Ok(FileHandle::new(Arc::clone(&self.disk_id), finfo))
    }
    
    fn opendir(&self, path: &str) -> FilesystemResult<DirectoryHandle> {
        qemu_log!("DebugFS: opendir called with path '{}'", path);
        Ok(DirectoryHandle {
            handle_id: self.id_arena.fetch_add(1, core::sync::atomic::Ordering::Relaxed) as _
        })
    }
    
    fn read(&self, handle: &mut FileHandle, buffer: &mut [u8]) -> FilesystemResult<u64> {
        qemu_log!("DebugFS: read called with handle {:?} and buffer of length {}", handle, buffer.len());
        Ok(0)
    }
    
    fn write(&self, handle: &mut FileHandle, buffer: &[u8]) -> FilesystemResult<u64> {
        qemu_log!("DebugFS: write called with handle {:?} and buffer of length {}", handle, buffer.len());
        Ok(0)
    }
    
    fn info(&self, path: &str) -> FilesystemResult<crate::entity::EntityInfo> {
        qemu_log!("DebugFS: info called with path '{}'", path);
        Err(FilesystemError::NotFound)
    }
    
    fn readdir(&self, _handle: &mut DirectoryHandle) -> FilesystemResult<crate::handles::directory::DirectoryEntry> {
        qemu_log!("DebugFS: readdir called");
        Err(FilesystemError::NotFound)
    }
    
    fn close(&self, handle: &mut FileHandle) -> FilesystemResult<()> {
        qemu_log!("DebugFS: close called");
        Err(FilesystemError::NotFound)
    }
    
    fn closedir(&self, handle: &mut DirectoryHandle) -> FilesystemResult<()> {
        qemu_log!("DebugFS: closedir called");
        Err(FilesystemError::NotFound)
    }
}