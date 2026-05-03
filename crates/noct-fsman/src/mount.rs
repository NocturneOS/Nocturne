use alloc::{boxed::Box, collections::btree_map::BTreeMap, string::String, sync::Arc, vec::Vec};
use lazy_static::lazy_static;
use noct_logger::qemu_log;
use spin::Mutex;

use crate::{FilesystemInstance, error::FilesystemResult};

pub type SharedFilesystemInstance = Arc<Box<dyn FilesystemInstance>>;

lazy_static! {
    pub static ref MOUNTED_DISKS: Mutex<Vec<SharedFilesystemInstance>> = Mutex::new(Vec::new());
}

/// Mount specific disk.
pub fn try_mount(disk_id: &str) -> FilesystemResult<SharedFilesystemInstance> {
    for fs in crate::store::STORE.lock().iter() {
        if let Some(instance) = fs.probe(disk_id) {
            qemu_log!("Probe of {} on disk {} succeeded.", fs.name(), disk_id);

            let instance = Arc::new(instance);

            MOUNTED_DISKS.lock().push(Arc::clone(&instance));
            
            return Ok(instance);
        }
    }

    Err(crate::error::FilesystemError::DiskNotRecognized)
}

pub fn get_handle(disk_id: &str) -> Option<SharedFilesystemInstance> {
    for instance in MOUNTED_DISKS.lock().iter() {
        if instance.fs().probe(disk_id).is_some() {
            return Some(Arc::clone(instance));
        }
    }

    None
}

pub fn scan_and_mount() {
    for disk in noct_diskman::disk_list() {
        if let Err(e) = try_mount(&disk.id) {
            qemu_log!("Failed to mount disk {}: {:?}", disk.id, e);
        }
    }
}