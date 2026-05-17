#![no_std]

extern crate alloc;

use core::{
    cell::Cell,
    ffi::{c_char, c_void},
};

use alloc::{boxed::Box, string::ToString, vec::Vec};
use noct_fsman::{
    entity::{self, EntityInfo, EntityType},
    error::{FilesystemError, FilesystemResult},
    handles::{
        directory::{DirectoryEntry, DirectoryHandle},
        file::{FileHandle, FileOpenMode},
    },
};
use noct_logger::{noct_time::repr::Time, qemu_log};
use spin::Mutex;
use tarfs::TarFS;

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
        }))
    }

    fn name(&self) -> &str {
        todo!()
    }
}

pub struct TarFSInstance {
    tar: Mutex<tarfs::TarFS>,

    id_arena: Mutex<Cell<usize>>,

    directory_handles: Mutex<Vec<(u64, alloc::vec::IntoIter<tarfs::Entity>)>>,
    // file_handles: Mutex<Vec<handles::FileHandleEntity>>,
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

    fn open(&self, path: &str, mode: FileOpenMode) -> FilesystemResult<FileHandle> {
        todo!()
    }

    fn read(&self, handle: &mut FileHandle, buffer: &mut [u8]) -> FilesystemResult<u64> {
        todo!()
    }

    fn write(&self, handle: &mut FileHandle, buffer: &[u8]) -> FilesystemResult<u64> {
        todo!()
    }

    fn opendir(&self, path: &str) -> FilesystemResult<DirectoryHandle> {
        let mut bind = self.tar.lock();
        let id = self.next_id();

        let list = bind
            .list_by_path_shallow(path)
            .map_err(|e| match e.kind() {
                no_std_io::io::ErrorKind::NotFound => FilesystemError::NotFound,
                _ => FilesystemError::Unknown,
            })?;

        self.directory_handles
            .lock()
            .push((id as _, list.into_iter()));

        todo!()
    }

    fn readdir(&self, handle: &mut DirectoryHandle) -> FilesystemResult<DirectoryEntry> {
        let mut bind = self.directory_handles.lock();

        let Some((_, dir_handle)) = bind.iter_mut().find(|(id, _)| *id == handle.handle_id) else {
            return Err(FilesystemError::InvalidEntity);
        };

        let entry = dir_handle.next().ok_or(FilesystemError::EndOfIterator)?;

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

    fn info(&self, path: &str) -> FilesystemResult<EntityInfo> {
        todo!()
    }

    fn close(&self, handle: &mut FileHandle) -> FilesystemResult<()> {
        todo!()
    }

    fn closedir(&self, handle: &mut DirectoryHandle) -> FilesystemResult<()> {
        self.directory_handles
            .lock()
            .retain(|&(id, _)| id as u64 != handle.handle_id);

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
//     let device = disk_device::DiskDevice::new(disk_name);

//     let mut fl = tarfs::TarFS::from_device(device).unwrap();

//     let path = ".".to_string() + raw_ptr_to_str(path);
//     let outbuf = core::slice::from_raw_parts_mut(buffer as *mut u8, count as _);

//     let result = fl.read_file(&path, offset as _, &mut outbuf[..count as usize]);

//     result.unwrap_or(0) as _
// }

// unsafe extern "C" fn fun_write(
//     _disk_name: *const c_char,
//     _b: *const c_char,
//     _c: u32,
//     _d: u32,
//     _e: *const c_void,
// ) -> u32 {
//     qemu_err!("Writing is not supported!");
//     0
// }

// unsafe extern "C" fn fun_info(disk_name: *const c_char, path: *const c_char) -> FSM_FILE {
//     let device = disk_device::DiskDevice::new(disk_name);

//     let mut fl = tarfs::TarFS::from_device(device).unwrap();

//     let path = ".".to_string() + raw_ptr_to_str(path);

//     let entity = match fl.find_file(&path) {
//         Err(_) => {
//             qemu_err!("{path} is missing!");
//             return FSM_FILE::missing()
//         },
//         Ok(e) => e,
//     };

//     let ftype = tarfs_type_to_fsm_type(entity._type);

//     FSM_FILE::with_data(
//         &entity.name,
//         0,
//         entity.size as _,
//         None,
//         ftype as _,
//         FSM_MOD_READ,
//     )
// }

// unsafe extern "C" fn fun_create(_disk_name: *const c_char, _b: *const c_char, _c: u32) -> i32 {
//     qemu_log!("Creating is not supported!");
//     0
// }

// unsafe extern "C" fn fun_delete(_disk_name: *const c_char, _b: *const c_char, _c: u32) -> i32 {
//     qemu_log!("Deleting is not supported!");
//     0
// }

// unsafe extern "C" fn fun_dir(disk_name: *const c_char, path: *const c_char, out: *mut FSM_DIR) {
//     let device = disk_device::DiskDevice::new(disk_name);

//     let mut fl = tarfs::TarFS::from_device(device).unwrap();

//     let path = ".".to_string() + &raw_ptr_to_str(path);

//     let data = fl.list_by_path_shallow(&path);

//     if data.is_err() {
//         *out = FSM_DIR::missing();
//         return;
//     }

//     let data = data.unwrap();

//     let files: Vec<FSM_FILE> = data
//         .into_iter()
//         .map(|elem| {
//             FSM_FILE::with_data(
//                 &elem.name,
//                 0,
//                 elem.size as _,
//                 None,
//                 tarfs_type_to_fsm_type(elem._type) as _,
//                 FSM_MOD_READ,
//             )
//         })
//         .collect();

//     let files = files.into_boxed_slice();

//     *out = FSM_DIR::with_files(files);
// }

// unsafe extern "C" fn fun_label(_disk_name: *const c_char, output_buffer: *mut c_char) {
//     output_buffer.copy_from(FSNAME.as_ptr() as *const _, FSNAME.len());
// }

// unsafe extern "C" fn fun_detect(disk_name: *const c_char) -> i32 {
//     let device = disk_device::DiskDevice::new(disk_name);

//     let fl = tarfs::TarFS::from_device(device);

//     if fl.is_some() {
//         1
//     } else {
//         0
//     }
// }

// #[no_mangle]
// pub extern "C" fn fs_tarfs_register() {
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
