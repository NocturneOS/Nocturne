#![no_std]

extern crate alloc;

use core::cell::Cell;

use alloc::{boxed::Box, vec::Vec};
use noct_fsman::{
    entity::{EntityInfo, EntityType},
    handles::{
        directory::{DirectoryEntry, DirectoryHandle},
        file::{FileHandle, FileOpenMode},
    },
};
use noct_logger::noct_time::repr::Time;
use spin::Mutex;

pub mod disk_device;

fn tarfs_type_to_fsm_type(tarfs_type: tarfs::Type) -> EntityType {
    match tarfs_type {
        tarfs::Type::Dir => EntityType::Directory,
        _ => EntityType::File,
    }
}

pub struct TarFilesystem;

impl noct_fsman::Filesystem for TarFilesystem {
    fn probe(
        &self,
        disk_id: &str,
    ) -> Option<alloc::boxed::Box<dyn noct_fsman::FilesystemInstance>> {
        let device = disk_device::DiskDevice::new(disk_id);

        let fl = tarfs::TarFS::from_device(device)?;

        Some(Box::new(TarFSInstance {
            tar: fl.into(),
            id_arena: Cell::new(0).into(),

            directory_handles: Vec::new().into(),
            file_handles: Vec::new().into(),
        }))
    }

    fn name(&self) -> &str {
        "tar"
    }
}

pub struct TarFSInstance {
    tar: Mutex<tarfs::TarFS>,

    id_arena: Mutex<Cell<usize>>,

    directory_handles: Mutex<Vec<(u64, alloc::vec::IntoIter<tarfs::Entity>)>>,
    file_handles: Mutex<Vec<(u64, tarfs::Entity)>>,
}

impl TarFSInstance {
    fn next_id(&self) -> usize {
        let arena = self.id_arena.lock();
        let id = arena.get();
        arena.set(id + 1);
        id
    }
}

impl noct_fsman::FilesystemInstance for TarFSInstance {
    fn fs(&self) -> &dyn noct_fsman::Filesystem {
        &TarFilesystem
    }

    fn open(&self, path: &str, mode: FileOpenMode) -> noct_io::Result<FileHandle> {
        if mode.contains(FileOpenMode::Write) || mode.contains(FileOpenMode::Truncate) {
            return Err(noct_io::error::Error::InvalidMode);
        }

        let mut bind = self.tar.lock();
        let id = self.next_id();

        let file = bind.find_file(path).map_err(|e| match e.kind() {
            no_std_io::io::ErrorKind::NotFound => noct_io::error::Error::NotFound,
            _ => noct_io::error::Error::Unknown,
        })?;

        self.file_handles.lock().push((id as _, file));

        todo!()
    }

    fn read(&self, handle: &mut FileHandle, buffer: &mut [u8]) -> noct_io::Result<u64> {
        let mut bind = self.tar.lock();
        let ent_bind = self.file_handles.lock();

        let (_, ent) = ent_bind
            .iter()
            .find(|&&(fh, _)| fh == handle.file_handle)
            .ok_or(noct_io::error::Error::InvalidHandle)?;

        bind.read_file_by_entity(ent, handle.position as _, buffer)
            .map_err(|_| noct_io::error::Error::IoError)?;

        todo!()
    }

    fn write(&self, _handle: &mut FileHandle, _buffer: &[u8]) -> noct_io::Result<u64> {
        Err(noct_io::error::Error::UnsupportedOperation)
    }

    fn opendir(&self, path: &str) -> noct_io::Result<DirectoryHandle> {
        let mut bind = self.tar.lock();
        let id = self.next_id();

        let list = bind
            .list_by_path_shallow(path)
            .map_err(|e| match e.kind() {
                no_std_io::io::ErrorKind::NotFound => noct_io::error::Error::NotFound,
                _ => noct_io::error::Error::Unknown,
            })?;

        self.directory_handles
            .lock()
            .push((id as _, list.into_iter()));

        todo!()
    }

    fn readdir(&self, handle: &mut DirectoryHandle) -> noct_io::Result<DirectoryEntry> {
        let mut bind = self.directory_handles.lock();

        let Some((_, dir_handle)) = bind.iter_mut().find(|(id, _)| *id == handle.handle_id) else {
            return Err(noct_io::error::Error::InvalidHandle);
        };

        let entry = dir_handle.next().ok_or(noct_io::error::Error::EndOfIterator)?;

        Ok(DirectoryEntry {
            name: entry.name.clone(),
            info: EntityInfo {
                node_id: entry.position as _,
                entity_type: tarfs_type_to_fsm_type(entry._type),
                size: entry.size as _,
                // TODO: Time retrieval
                created_at: Time::epoch(),
                modified_at: Time::epoch(),
            },
        })
    }

    fn info(&self, path: &str) -> noct_io::Result<EntityInfo> {
        let mut bind = self.tar.lock();

        let file = bind.find_file(path).map_err(|e| match e.kind() {
            no_std_io::io::ErrorKind::NotFound => noct_io::error::Error::NotFound,
            _ => noct_io::error::Error::Unknown,
        })?;

        Ok(EntityInfo {
            node_id: file.position as _,
            entity_type: tarfs_type_to_fsm_type(file._type),
            size: file.size as _,
            created_at: Time::epoch(),
            modified_at: Time::epoch(),
        })
    }

    fn close(&self, handle: &mut FileHandle) -> noct_io::Result<()> {
        self.file_handles
            .lock()
            .retain(|&(id, _)| id as u64 != handle.file_handle);

        Ok(())
    }

    fn closedir(&self, handle: &mut DirectoryHandle) -> noct_io::Result<()> {
        self.directory_handles
            .lock()
            .retain(|&(id, _)| id as u64 != handle.handle_id);

        Ok(())
    }

    fn mkfile(&self, _path: &str) -> noct_io::Result<()> {
        Err(noct_io::error::Error::ReadOnly)
    }

    fn mkdir(&self, _path: &str) -> noct_io::Result<()> {
        Err(noct_io::error::Error::ReadOnly)
    }

    fn remove(&self, _path: &str) -> noct_io::Result<()> {
        Err(noct_io::error::Error::ReadOnly)
    }
}
