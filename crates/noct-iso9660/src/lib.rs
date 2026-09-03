#![no_std]

extern crate alloc;

mod device;
mod handles;

use core::cell::Cell;

use alloc::{borrow::ToOwned, boxed::Box, string::String, sync::Arc, vec::Vec};
use iso9660_simple::{ISODirectoryEntry, ISO9660};
use noct_fsman::{
    entity::EntityInfo,
    handles::{
        directory::{DirectoryEntry, DirectoryHandle},
        file::{FileHandle, FileOpenMode},
    },
    Filesystem, FilesystemInstance,
};
use spin::Mutex;

use crate::{device::Device};

#[inline]
fn iso_type_to_fsman_type(entry: &ISODirectoryEntry) -> noct_fsman::entity::EntityType {
    if entry.is_folder() {
        noct_fsman::entity::EntityType::Directory
    } else {
        noct_fsman::entity::EntityType::File
    }
}

#[inline]
fn iso_datetime_to_fsm(entry: &ISODirectoryEntry) -> noct_time::repr::DateTime {
    noct_time::repr::DateTime::new(
        1900 + entry.record.datetime.year as u16,
        entry.record.datetime.month as _,
        entry.record.datetime.day as _,
        entry.record.datetime.hour as _,
        entry.record.datetime.minute as _,
        entry.record.datetime.second as _,
    )
    .unwrap()
}

pub struct ISO9660Filesystem;

impl Filesystem for ISO9660Filesystem {
    fn probe(&self, disk_id: &str) -> Option<Box<dyn FilesystemInstance>> {
        let iso = ISO9660::from_device(Device::new(disk_id))?;

        Some(Box::new(ISO9660FilesystemInstance {
            inst: iso.into(),
            disk_id: Arc::new(disk_id.to_owned()),
            id_arena: Cell::new(0).into(),
            directory_handles: Vec::new().into(),
            file_handles: Vec::new().into(),
        }))
    }

    fn name(&self) -> &str {
        "iso9660"
    }
}

struct ISO9660FilesystemInstance {
    inst: Mutex<ISO9660>,

    disk_id: Arc<String>,
    id_arena: Mutex<Cell<usize>>,

    directory_handles: Mutex<Vec<handles::DirectoryHandleEntity>>,
    file_handles: Mutex<Vec<handles::FileHandleEntity>>,
}

impl ISO9660FilesystemInstance {
    fn next_id(&self) -> usize {
        let arena = self.id_arena.lock();
        let id = arena.get();
        arena.set(id + 1);
        id
    }
}

impl FilesystemInstance for ISO9660FilesystemInstance {
    fn fs(&self) -> &dyn Filesystem {
        &ISO9660Filesystem
    }

    fn open(&self, path: &str, mode: FileOpenMode) -> noct_io::Result<FileHandle> {
        if mode.contains(FileOpenMode::Truncate) | mode.contains(FileOpenMode::Write) {
            return Err(noct_io::error::Error::InvalidMode);
        }

        let mut inst = self.inst.lock();

        let Some(entry) = iso9660_simple::helpers::get_directory_entry_by_path(&mut *inst, path)
        else {
            return Err(noct_io::error::Error::NotFound);
        };

        let id = self.next_id();

        self.file_handles.lock().push(handles::FileHandleEntity {
            id,
            file_entry: entry,
        });

        drop(inst);

        Ok(FileHandle::new(
            id as _,
            Arc::clone(&self.disk_id),
            self.info(path)?,
        ))
    }

    fn read(&self, handle: &mut FileHandle, buffer: &mut [u8]) -> noct_io::Result<u64> {
        let mut inst = self.inst.lock();
        let mut bind = self.file_handles.lock();

        let Some(file_handle) = bind
            .iter_mut()
            .find(|entity| entity.id == handle.file_handle as usize)
        else {
            return Err(noct_io::error::Error::InvalidEntity);
        };

        let count = inst
            .read_file(&file_handle.file_entry, handle.position as _, buffer)
            .ok_or(noct_io::error::Error::Unknown)?;

        // TODO: When ISO9660::read_file will return read byte count, pass it here.
        Ok(count as _)
    }

    fn write(&self, _handle: &mut FileHandle, _buffer: &[u8]) -> noct_io::Result<u64> {
        Err(noct_io::error::Error::ReadOnly)
    }

    fn opendir(&self, path: &str) -> noct_io::Result<DirectoryHandle> {
        let new_id = self.next_id();
        let mut inst = self.inst.lock();

        let Some(entry) = iso9660_simple::helpers::get_directory_entry_by_path(&mut *inst, path)
        else {
            return Err(noct_io::error::Error::NotFound);
        };

        if !entry.is_folder() {
            return Err(noct_io::error::Error::InvalidEntity);
        }

        self.directory_handles
            .lock()
            .push(handles::DirectoryHandleEntity {
                id: new_id,
                directory_entry: entry,
                iterator_position: 0,
            });

        Ok(DirectoryHandle {
            disk_id: self.disk_id.clone(),
            handle_id: new_id as _,
        })
    }

    fn readdir(&self, handle: &mut DirectoryHandle) -> noct_io::Result<DirectoryEntry> {
        let mut inst = self.inst.lock();

        let mut bind = self.directory_handles.lock();

        let Some(dir_handle) = bind
            .iter_mut()
            .find(|entity| entity.id == handle.handle_id as usize)
        else {
            return Err(noct_io::error::Error::InvalidEntity);
        };

        let iter = inst.read_directory(dir_handle.directory_entry.lsb_position() as _);

        let entry = (&iter)
            .nth(dir_handle.iterator_position)
            .ok_or(noct_io::error::Error::EndOfIterator)?;

        dir_handle.iterator_position += 1;

        Ok(DirectoryEntry {
            info: EntityInfo {
                node_id: entry.lsb_position() as _,
                entity_type: iso_type_to_fsman_type(&entry),
                size: entry.file_size() as _,
                created_at: iso_datetime_to_fsm(&entry),
                modified_at: iso_datetime_to_fsm(&entry),
            },
            name: entry.name,
        })
    }

    fn info(&self, path: &str) -> noct_io::Result<EntityInfo> {
        let mut inst = self.inst.lock();

        let Some(entry) = iso9660_simple::helpers::get_directory_entry_by_path(&mut *inst, path)
        else {
            return Err(noct_io::error::Error::NotFound);
        };

        Ok(EntityInfo {
            node_id: entry.lsb_position() as _,
            entity_type: iso_type_to_fsman_type(&entry),
            size: entry.file_size() as _,
            created_at: iso_datetime_to_fsm(&entry),
            modified_at: iso_datetime_to_fsm(&entry),
        })
    }

    fn close(&self, handle: &mut FileHandle) -> noct_io::Result<()> {
        self.file_handles
            .lock()
            .retain(|x| x.id as u64 != handle.file_handle);

        Ok(())
    }

    fn closedir(&self, handle: &mut DirectoryHandle) -> noct_io::Result<()> {
        self.directory_handles
            .lock()
            .retain(|x| x.id as u64 != handle.handle_id);

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
