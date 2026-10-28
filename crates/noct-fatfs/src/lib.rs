#![no_std]

extern crate alloc;

mod handles;

use core::{
    cell::Cell,
    ffi::{c_char, c_void},
};

use alloc::{
    boxed::Box,
    string::{String, ToString},
    sync::Arc,
    vec,
    vec::Vec,
};
use fatfs::{FsOptions, IntoStorage, OemCpConverter, Read, Seek, SeekFrom, Write};
use noct_fsman::{
    entity::{EntityInfo, EntityType},
    handles::{
        directory::DirectoryHandle,
        file::{self, FileHandle},
    },
};
use noct_logger::qemu_log;
use spin::Mutex;

use crate::handles::{DirectoryHandleEntity, FileHandleEntity};

static FSNAME: &[u8] = b"FATFS\0";

pub struct FAT32Filesystem;

impl noct_fsman::Filesystem for FAT32Filesystem {
    fn probe(
        &self,
        disk_id: &str,
    ) -> Option<alloc::boxed::Box<dyn noct_fsman::FilesystemInstance>> {
        let fat = fatfs::FileSystem::new(
            DiskFile {
                disk_name: disk_id.to_string(),
                position: 0,
            },
            FsOptions::new(),
        );

        fat.map(|x| {
            Box::new(FAT32FilesystemInstance {
                inst: x.into(),
                disk_id: disk_id.to_string().into(),
                id_arena: Mutex::new(Cell::new(0)),
                directory_handles: Mutex::new(vec![]),
                file_handles: Mutex::new(vec![]),
            }) as Box<dyn noct_fsman::FilesystemInstance>
        })
        .ok()
    }

    fn name(&self) -> &str {
        "fat"
    }
}

pub struct FAT32FilesystemInstance {
    inst: Mutex<fatfs::FileSystem<DiskFile>>,

    disk_id: Arc<String>,
    id_arena: Mutex<Cell<usize>>,

    directory_handles: Mutex<Vec<handles::DirectoryHandleEntity>>,
    file_handles: Mutex<Vec<handles::FileHandleEntity>>,
}

impl FAT32FilesystemInstance {
    fn next_id(&self) -> usize {
        let arena = self.id_arena.lock();
        let id = arena.get();
        arena.set(id + 1);
        id
    }
}

fn convert_error<T>(error: fatfs::Error<T>) -> noct_io::error::Error {
    match error {
        fatfs::Error::Io(_) => noct_io::error::Error::IoError, // todo!("FatFS encountered I/O error, but conversions are unimplemented."),
        fatfs::Error::UnexpectedEof => noct_io::error::Error::Unknown,
        fatfs::Error::WriteZero => noct_io::error::Error::Unknown,
        fatfs::Error::InvalidInput => noct_io::error::Error::MemoryError,
        fatfs::Error::NotFound => noct_io::error::Error::NotFound,
        fatfs::Error::AlreadyExists => noct_io::error::Error::AlreadyExists,
        fatfs::Error::DirectoryIsNotEmpty => noct_io::error::Error::Unknown,
        fatfs::Error::CorruptedFileSystem => noct_io::error::Error::FilesystemNotRecognized,
        fatfs::Error::NotEnoughSpace => noct_io::error::Error::NoSpace,
        fatfs::Error::InvalidFileNameLength => noct_io::error::Error::InvalidPath,
        fatfs::Error::UnsupportedFileNameCharacter => noct_io::error::Error::InvalidPath,
        _ => todo!("FatFS: Process more errors."),
    }
}

fn direntry_to_entity<IO: fatfs::ReadWriteSeek, TP, OCC: OemCpConverter>(
    dirent: fatfs::DirEntry<IO, TP, OCC>,
) -> noct_io::Result<noct_fsman::entity::EntityInfo> {
    let entity_type = match dirent.is_dir() {
        true => EntityType::Directory,
        false => EntityType::File,
    };

    let size = dirent.len();
    let created_at = dirent.created();
    let modified_at = dirent.modified();

    let node_id = match dirent.to_file().extents().next() {
        Some(Ok(x)) => x.offset,
        _ => return Err(noct_io::error::Error::Unknown),
    };

    // TODO: Fork rust-fatfs and allow `first_cluster` be visible, to make an unique ID for each entry.
    // let node_id = 1;

    Ok(EntityInfo {
        node_id,
        entity_type,
        size,
        created_at: noct_time::repr::DateTime::new(
            created_at.date.year,
            created_at.date.month as _,
            created_at.date.day as _,
            created_at.time.hour as _,
            created_at.time.min as _,
            created_at.time.sec as _,
            0
        )
        .unwrap(),
        modified_at: noct_time::repr::DateTime::new(
            modified_at.date.year,
            modified_at.date.month as _,
            modified_at.date.day as _,
            modified_at.time.hour as _,
            modified_at.time.min as _,
            modified_at.time.sec as _,
            0
        )
        .unwrap(),
    })
}

impl noct_fsman::FilesystemInstance for FAT32FilesystemInstance {
    fn fs(&self) -> &dyn noct_fsman::Filesystem {
        todo!()
    }

    fn open(
        &self,
        path: &str,
        mode: noct_fsman::handles::file::FileOpenMode,
    ) -> noct_io::Result<noct_fsman::handles::file::FileHandle> {
        let lock = self.inst.lock();
        
        lock.root_dir().open_file(path).map_err(convert_error)?;
        
        let fh = self.next_id();
        
        self.file_handles.lock().push(FileHandleEntity {
            id: fh,
            file_path: path.to_string(),
        });

        drop(lock);

        Ok(FileHandle::new(
            fh as _,
            self.disk_id.clone(),
            self.info(path)?,
        ))
    }

    fn read(
        &self,
        handle: &mut noct_fsman::handles::file::FileHandle,
        buffer: &mut [u8],
    ) -> noct_io::Result<u64> {
        let lock = self.file_handles.lock();
        let f_handle = lock
            .iter()
            .find(|x| x.id as u64 == handle.file_handle)
            .ok_or(noct_io::error::Error::Unknown)?;

        let path = &f_handle.file_path;

        let fslock = self.inst.lock();

        let mut file = fslock.root_dir().open_file(path).map_err(convert_error)?;

        let read_count = file.read(buffer).map_err(convert_error)?;

        Ok(read_count as _)
    }

    fn write(
        &self,
        handle: &mut noct_fsman::handles::file::FileHandle,
        buffer: &[u8],
    ) -> noct_io::Result<u64> {
        let lock = self.file_handles.lock();
        let f_handle = lock
            .iter()
            .find(|x| x.id as u64 == handle.file_handle)
            .ok_or(noct_io::error::Error::Unknown)?;

        let path = &f_handle.file_path;

        let fslock = self.inst.lock();

        let mut file = fslock.root_dir().open_file(path).map_err(convert_error)?;

        let read_count = file.write(buffer).map_err(convert_error)?;

        Ok(read_count as _)
    }

    fn opendir(
        &self,
        path: &str,
    ) -> noct_io::Result<noct_fsman::handles::directory::DirectoryHandle> {
        let lock = self.inst.lock();

        lock.root_dir().open_dir(path).map_err(convert_error)?;

        let dh = self.next_id();

        self.directory_handles.lock().push(DirectoryHandleEntity {
            id: dh,
            directory_path: path.to_string(),
            iterator_position: 0,
        });

        Ok(DirectoryHandle {
            handle_id: dh as _,
            disk_id: self.disk_id.clone(),
        })
    }

    fn readdir(
        &self,
        handle: &mut noct_fsman::handles::directory::DirectoryHandle,
    ) -> noct_io::Result<noct_fsman::handles::directory::DirectoryEntry> {
        let mut lock = self.directory_handles.lock();

        let inner_handle = lock
            .iter_mut()
            .find(|x| x.id as u64 == handle.handle_id)
            .ok_or(noct_io::error::Error::Unknown)?;

        let path = &inner_handle.directory_path;

        let fslock = self.inst.lock();

        let dir = fslock.root_dir().open_dir(path).map_err(convert_error)?;

        let element = dir
            .iter()
            .nth(inner_handle.iterator_position)
            .ok_or(noct_io::error::Error::EndOfIterator)?
            .map_err(convert_error)?;

        let name = element.file_name();

        let entity = direntry_to_entity(element)?;

        Ok(noct_fsman::handles::directory::DirectoryEntry { name, info: entity })
    }

    fn info(&self, path: &str) -> noct_io::Result<noct_fsman::entity::EntityInfo> {
        let lock = self.inst.lock();

        qemu_log!("Path: {path:?}");

        let (mut dirpath, filename) = path
            .rsplit_once('/')
            .ok_or(noct_io::error::Error::InvalidPath)?;

        dirpath = dirpath.trim_start_matches('/');

        qemu_log!("Directory: {dirpath:?}; Filename: {filename:?}");

        let dir = if dirpath.is_empty() {
            lock.root_dir()
        } else {
            lock.root_dir().open_dir(dirpath).map_err(convert_error)?
        };

        let file_info = dir
            .iter()
            .find(|x| x.as_ref().unwrap().file_name() == filename)
            .ok_or(noct_io::error::Error::NotFound)?
            .map_err(convert_error)?;

        direntry_to_entity(file_info)
    }

    fn close(&self, handle: &mut noct_fsman::handles::file::FileHandle) -> noct_io::Result<()> {
        self.file_handles
            .lock()
            .retain(|x| x.id as u64 != handle.file_handle);

        Ok(())
    }

    fn closedir(
        &self,
        handle: &mut noct_fsman::handles::directory::DirectoryHandle,
    ) -> noct_io::Result<()> {
        self.directory_handles
            .lock()
            .retain(|x| x.id as u64 != handle.handle_id);

        Ok(())
    }

    fn mkfile(&self, path: &str) -> noct_io::Result<()> {
        let lock = self.inst.lock();

        lock.root_dir().create_file(path).map_err(convert_error)?;

        Ok(())
    }

    fn mkdir(&self, path: &str) -> noct_io::Result<()> {
        let lock = self.inst.lock();

        lock.root_dir().create_dir(path).map_err(convert_error)?;

        Ok(())
    }

    fn remove(&self, path: &str) -> noct_io::Result<()> {
        let lock = self.inst.lock();

        lock.root_dir().remove(path).map_err(convert_error)?;

        Ok(())
    }
}

struct DiskFile {
    disk_name: String,
    position: u64,
}

impl fatfs::IoBase for DiskFile {
    type Error = ();
}

impl fatfs::Read for DiskFile {
    fn read(&mut self, buffer: &mut [u8]) -> Result<usize, ()> {
        let size =
            noct_diskman::read_bytes(&self.disk_name, self.position, buffer).map_err(|_| ())?;

        self.position += size as u64;

        Ok(size as _)
    }
}

impl fatfs::Write for DiskFile {
    fn write(&mut self, buffer: &[u8]) -> Result<usize, Self::Error> {
        let size =
            noct_diskman::write_bytes(&self.disk_name, self.position, buffer).map_err(|_| ())?;

        self.position += size as u64;

        Ok(size as _)
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
}

impl fatfs::Seek for DiskFile {
    fn seek(&mut self, pos: SeekFrom) -> Result<u64, Self::Error> {
        match pos {
            SeekFrom::Start(p) => {
                self.position = p;
            }
            SeekFrom::End(_p) => {
                todo!("Check fatfs::SeekFrom::End!");
                // self.position = (self.disk.capacity() as i64 - p) as u64;
            }
            SeekFrom::Current(p) => {
                self.position = (self.position as i64 + p) as u64;
            }
        };

        Ok(self.position)
    }
}
