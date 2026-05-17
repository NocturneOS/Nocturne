#![no_std]

extern crate alloc;

mod device;
mod handles;

use core::{
    cell::Cell,
    ffi::{c_char, c_void},
};

use alloc::{borrow::ToOwned, boxed::Box, string::String, sync::Arc, vec::Vec};
use iso9660_simple::{helpers::get_directory_entry_by_path, ISODirectoryEntry, Read, ISO9660};
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
            return Err(FilesystemError::UnsupportedOperation);
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

        let count = inst.read_file(&file_handle.file_entry, handle.position as _, buffer)
            .ok_or(FilesystemError::Unknown)?;

        // TODO: When ISO9660::read_file will return read byte count, pass it here.
        Ok(count as _)
    }

    fn write(&self, _handle: &mut FileHandle, _buffer: &[u8]) -> FilesystemResult<u64> {
        Err(FilesystemError::UnsupportedOperation)
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
}

// unsafe extern "C" fn fun_read(
//     disk_name: *const c_char,
//     path: *const c_char,
//     offset: u32,
//     count: u32,
//     buffer: *mut c_void,
// ) -> u32 {
//     let mut fl = iso9660_simple::ISO9660::from_device(ThatDisk {
//         disk_name: raw_ptr_to_str(disk_name),
//     })
//     .unwrap();

//     let rpath = raw_ptr_to_str(path);

//     let entries = match get_directory_entry_by_path(&mut fl, rpath) {
//         Some(entry) => entry,
//         None => return 0,
//     };

//     let outbuf = core::slice::from_raw_parts_mut(buffer as *mut u8, count as _);

//     let rd = noct_diskman::read(
//         raw_ptr_to_str(disk_name),
//         ((entries.lsb_position() * 2048) + offset) as u64,
//         outbuf,
//     );

//     rd as _
// }

// unsafe extern "C" fn fun_write(
//     _disk_name: *const c_char,
//     _path: *const c_char,
//     _c: u32,
//     _d: u32,
//     _e: *const c_void,
// ) -> u32 {
//     qemu_err!("Writing is not supported!");
//     0
// }

// unsafe extern "C" fn fun_info(disk_name: *const c_char, path: *const c_char) -> FSM_FILE {
//     let mut fl = iso9660_simple::ISO9660::from_device(ThatDisk {
//         disk_name: raw_ptr_to_str(disk_name),
//     })
//     .unwrap();

//     let rpath = raw_ptr_to_str(path);

//     let entry = get_directory_entry_by_path(&mut fl, rpath);

//     if entry.is_none() {
//         return FSM_FILE::missing();
//     }

//     let entry = entry.unwrap();
//     let ftype = iso_type_to_fsm_type(&entry);

//     FSM_FILE::with_data(
//         &entry.name,
//         0,
//         entry.record.data_length.lsb,
//         Some(iso_datetime_to_fsm(&entry)),
//         ftype as _,
//         FSM_MOD_READ,
//     )
// }

// unsafe extern "C" fn fun_create(_disk_name: *const c_char, _b: *const c_char, _c: u32) -> i32 {
//     qemu_err!("Creating is not supported!");
//     0
// }

// unsafe extern "C" fn fun_delete(_disk_name: *const c_char, _b: *const c_char, _c: u32) -> i32 {
//     qemu_err!("Deleting is not supported!");
//     0
// }

// unsafe extern "C" fn fun_dir(disk_name: *const c_char, path: *const c_char, out: *mut FSM_DIR) {
//     let mut fl = iso9660_simple::ISO9660::from_device(ThatDisk {
//         disk_name: raw_ptr_to_str(disk_name),
//     })
//     .unwrap();

//     let path = raw_ptr_to_str(path);

//     qemu_note!("Path requested: {path}");

//     let root = iso9660_simple::helpers::get_directory_entry_by_path(&mut fl, path);

//     let root = match root {
//         Some(root) => root,
//         None => {
//             *out = FSM_DIR::missing();
//             return;
//         }
//     };

//     let root = fl.read_directory(root.record.lba.lsb as _);

//     let files: Vec<FSM_FILE> = root
//         .map(|elem| {
//             FSM_FILE::with_data(
//                 &elem.name,
//                 0,
//                 elem.record.data_length.lsb,
//                 Some(iso_datetime_to_fsm(&elem)),
//                 iso_type_to_fsm_type(&elem),
//                 FSM_MOD_READ,
//             )
//         })
//         .collect();

//     let files = files.into_boxed_slice();

//     *out = FSM_DIR::with_files(files);
// }

// unsafe extern "C" fn fun_label(_disk_name: *const c_char, output: *mut c_char) {
//     output.copy_from(FSNAME.as_ptr() as *const _, FSNAME.len());
// }

// unsafe extern "C" fn fun_detect(disk_name: *const c_char) -> i32 {
//     let mut buffer = [0u8; 5];

//     let disk_name = raw_ptr_to_str(disk_name);
//     noct_diskman::read(disk_name, 0x8001, &mut buffer);

//     if ISO9660_OEM != buffer {
//         // qemu_err!(
//         //     "Not valid ISO! (Disk: {disk_name:?})"
//         // );

//         return 0;
//     }

//     qemu_log!("Detected ISO! {disk_name:?}");

//     1
// }

// #[no_mangle]
// pub extern "C" fn fs_iso9660_init() {
//     unsafe {
//         noct_fs_sys::fsm_reg(
//             FSNAME.as_ptr() as *const _,
//             Some(fun_read),
//             Some(fun_write),
//             Some(fun_info),
//             Some(fun_create),
//             Some(fun_delete),
//             Some(fun_dir),
//             Some(fun_label),
//             Some(fun_detect),
//         )
//     };
// }
