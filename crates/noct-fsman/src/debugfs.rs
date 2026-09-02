use alloc::{
    boxed::Box,
    string::{String, ToString},
    sync::Arc,
};
use noct_io::error::Error;
use core::sync::atomic::{AtomicUsize, Ordering};
use noct_logger::qemu_log;
use noct_time::repr::DateTime;

use crate::{
    DirectoryHandle, FileHandle, FileOpenMode, Filesystem, FilesystemInstance,
    entity::{EntityInfo, EntityType},
};

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

    fn open(&self, path: &str, mode: FileOpenMode) -> noct_io::Result<FileHandle> {
        qemu_log!(
            "DebugFS: open called with path '{}' and mode {:?}",
            path,
            mode
        );

        let finfo = EntityInfo {
            node_id: 0,
            entity_type: EntityType::File,
            size: 0,
            created_at: DateTime::epoch(),
            modified_at: DateTime::epoch(),
        };

        Ok(FileHandle::new(
            self.id_arena.fetch_add(1, Ordering::Relaxed) as _,
            Arc::clone(&self.disk_id),
            finfo,
        ))
    }

    fn read(&self, handle: &mut FileHandle, buffer: &mut [u8]) -> noct_io::Result<u64> {
        qemu_log!(
            "DebugFS: read called with handle {:?} and buffer of length {}",
            handle,
            buffer.len()
        );
        Ok(0)
    }

    fn write(&self, handle: &mut FileHandle, buffer: &[u8]) -> noct_io::Result<u64> {
        qemu_log!(
            "DebugFS: write called with handle {:?} and buffer of length {}",
            handle,
            buffer.len()
        );
        Ok(0)
    }

    fn opendir(&self, path: &str) -> noct_io::Result<DirectoryHandle> {
        qemu_log!("DebugFS: opendir called with path '{}'", path);

        Ok(DirectoryHandle {
            disk_id: self.disk_id.clone(),
            handle_id: self.id_arena.fetch_add(1, Ordering::Relaxed) as _,
        })
    }

    fn readdir(
        &self,
        _handle: &mut DirectoryHandle,
    ) -> noct_io::Result<crate::handles::directory::DirectoryEntry> {
        qemu_log!("DebugFS: readdir called");
        Err(Error::NotFound)
    }

    fn info(&self, path: &str) -> noct_io::Result<EntityInfo> {
        qemu_log!("DebugFS: info called with path '{}'", path);
        Err(Error::NotFound)
    }

    fn close(&self, _handle: &mut FileHandle) -> noct_io::Result<()> {
        qemu_log!("DebugFS: close called");
        Err(Error::NotFound)
    }

    fn closedir(&self, _handle: &mut DirectoryHandle) -> noct_io::Result<()> {
        qemu_log!("DebugFS: closedir called");
        Err(Error::NotFound)
    }

    fn mkfile(&self, path: &str) -> noct_io::Result<()> {
        qemu_log!("DebugFS: mkfile called ({path:?})");
        Ok(())
    }

    fn mkdir(&self, path: &str) -> noct_io::Result<()> {
        qemu_log!("DebugFS: mkfile called ({path:?})");
        Ok(())
    }

    fn remove(&self, path: &str) -> noct_io::Result<()> {
        qemu_log!("DebugFS: remove called ({path:?})");
        Ok(())
    }
}
