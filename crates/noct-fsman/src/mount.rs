use alloc::{borrow::ToOwned, boxed::Box, string::String, sync::Arc, vec::Vec};
use lazy_static::lazy_static;
use noct_io::error::Error;
use noct_logger::qemu_log;
use spin::Mutex;

use crate::{FilesystemInstance};

pub type SharedFilesystemInstance = Arc<Box<dyn FilesystemInstance>>;

lazy_static! {
    /// Mapping from disk ID to FS instance.
    /// 
    /// TODO: Make a virtual binding from non-existent drive `disks` to virtual `devfs` filesystem to allow accessing
    /// disks directly (e.g. "disks:/ata0").
    pub static ref MOUNTED_DISKS: Mutex<Vec<(String, SharedFilesystemInstance)>> =
        Mutex::new(Vec::new());
}

/// Mount specific disk.
pub fn try_mount(disk_id: &str) -> noct_io::Result<SharedFilesystemInstance> {
    for fs in crate::store::STORE.lock().iter() {
        if let Some(instance) = fs.probe(disk_id) {
            qemu_log!("Probe of {} on disk {} succeeded.", fs.name(), disk_id);

            let instance = Arc::new(instance);

            MOUNTED_DISKS
                .lock()
                .push((disk_id.to_owned(), Arc::clone(&instance)));

            return Ok(instance);
        }
    }

    Err(Error::FilesystemNotRecognized)
}

pub fn get_handle(disk_id: &str) -> Option<SharedFilesystemInstance> {
    for (name, instance) in MOUNTED_DISKS.lock().iter() {
        if name == disk_id {
            return Some(Arc::clone(instance));
        }
    }

    None
}

pub fn scan_and_mount() {
    for disk in noct_diskman::disk_list() {
        qemu_log!("Probing disk {}", disk.id);

        if let Err(e) = try_mount(&disk.id) {
            qemu_log!("Failed to mount disk {}: {:?}", disk.id, e);
        }
    }
}
