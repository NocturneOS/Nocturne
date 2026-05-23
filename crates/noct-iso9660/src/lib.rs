#![no_std]

extern crate alloc;

mod device;
mod handles;

use core::cell::Cell;

use alloc::{borrow::ToOwned, boxed::Box, string::String, sync::Arc, vec::Vec};
use iso9660_simple::{ISODirectoryEntry, Read, ISO9660};
use noct_fsman::{
    entity::EntityInfo,
    error::{FilesystemError, FilesystemResult},
    handles::{
        directory::{DirectoryEntry, DirectoryHandle},
        file::{FileHandle, FileOpenMode},
    },
    Filesystem, FilesystemInstance,
};
use noct_logger::qemu_log;
use spin::Mutex;

use crate::{device::Device, handles::FileHandleEntity};

const ISO9660_OEM: [u8; 5] = [67, 68, 48, 48, 49];

#[inline]
fn iso_type_to_fsman_type(entry: &ISODirectoryEntry) -> noct_fsman::entity::EntityType {
    if entry.is_folder() {
        noct_fsman::entity::EntityType::Directory
    } else {
        noct_fsman::entity::EntityType::File
    }
}

#[inline]
fn iso_datetime_to_fsm(entry: &ISODirectoryEntry) -> noct_time::repr::Time {
    noct_time::repr::Time::new(
        1900 + entry.record.datetime.year as u16,
        entry.record.datetime.month as _,
        entry.record.datetime.day as _,
        entry.record.datetime.hour as _,
        entry.record.datetime.minute as _,
        entry.record.datetime.second as _,
    )
    .unwrap()
}

struct DiskDevice {
    diskname: String,
}

impl Read for DiskDevice {
    fn read(&mut self, position: usize, buffer: &mut [u8]) -> Option<()> {
        noct_diskman::read_bytes(&self.diskname, position as _, buffer)
            .map(|_| ())
            .ok()
    }
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

    fn open(&self, path: &str, mode: FileOpenMode) -> FilesystemResult<FileHandle> {
        if mode.contains(FileOpenMode::Truncate) | mode.contains(FileOpenMode::Write) {
            return Err(FilesystemError::InvalidMode);
        }

        let mut inst = self.inst.lock();

        let Some(entry) = iso9660_simple::helpers::get_directory_entry_by_path(&mut *inst, path)
        else {
            return Err(FilesystemError::NotFound);
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

    fn read(&self, handle: &mut FileHandle, buffer: &mut [u8]) -> FilesystemResult<u64> {
        let mut inst = self.inst.lock();
        let mut bind = self.file_handles.lock();

        let Some(file_handle) = bind
            .iter_mut()
            .find(|entity| entity.id == handle.file_handle as usize)
        else {
            return Err(FilesystemError::InvalidEntity);
        };

        let count = inst
            .read_file(&file_handle.file_entry, handle.position as _, buffer)
            .ok_or(FilesystemError::Unknown)?;

        // TODO: When ISO9660::read_file will return read byte count, pass it here.
        Ok(count as _)
    }

    fn write(&self, _handle: &mut FileHandle, _buffer: &[u8]) -> FilesystemResult<u64> {
        Err(FilesystemError::ReadOnly)
    }

    fn opendir(&self, path: &str) -> FilesystemResult<DirectoryHandle> {
        let new_id = self.next_id();
        let mut inst = self.inst.lock();

        let Some(entry) = iso9660_simple::helpers::get_directory_entry_by_path(&mut *inst, path)
        else {
            return Err(FilesystemError::NotFound);
        };

        if !entry.is_folder() {
            return Err(FilesystemError::InvalidEntity);
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

    fn readdir(&self, handle: &mut DirectoryHandle) -> FilesystemResult<DirectoryEntry> {
        let mut inst = self.inst.lock();

        let mut bind = self.directory_handles.lock();

        let Some(dir_handle) = bind
            .iter_mut()
            .find(|entity| entity.id == handle.handle_id as usize)
        else {
            return Err(FilesystemError::InvalidEntity);
        };

        let iter = inst.read_directory(dir_handle.directory_entry.lsb_position() as _);

        let entry = iter
            .skip(dir_handle.iterator_position)
            .next()
            .ok_or(FilesystemError::EndOfIterator)?;

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

    fn info(&self, path: &str) -> FilesystemResult<EntityInfo> {
        let mut inst = self.inst.lock();

        let Some(entry) = iso9660_simple::helpers::get_directory_entry_by_path(&mut *inst, path)
        else {
            return Err(FilesystemError::NotFound);
        };

        Ok(EntityInfo {
            node_id: entry.lsb_position() as _,
            entity_type: iso_type_to_fsman_type(&entry),
            size: entry.file_size() as _,
            created_at: iso_datetime_to_fsm(&entry),
            modified_at: iso_datetime_to_fsm(&entry),
        })
    }

    fn close(&self, handle: &mut FileHandle) -> FilesystemResult<()> {
        self.file_handles
            .lock()
            .retain(|x| x.id as u64 != handle.file_handle);

        Ok(())
    }

    fn closedir(&self, handle: &mut DirectoryHandle) -> FilesystemResult<()> {
        self.directory_handles
            .lock()
            .retain(|x| x.id as u64 != handle.handle_id);

        Ok(())
    }

    fn mkfile(&self, _path: &str) -> FilesystemResult<()> {
        Err(FilesystemError::ReadOnly)
    }

    fn mkdir(&self, _path: &str) -> FilesystemResult<()> {
        Err(FilesystemError::ReadOnly)
    }

    fn remove(&self, _path: &str) -> FilesystemResult<()> {
        Err(FilesystemError::ReadOnly)
    }
}
