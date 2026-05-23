use alloc::boxed::Box;

use crate::{Filesystem, FilesystemInstance};

pub struct NullFilesystem;

impl Filesystem for NullFilesystem {
    fn probe(&self, _disk_id: &str) -> Option<Box<dyn FilesystemInstance>> {
        None
    }

    fn name(&self) -> &str {
        "nullfs"
    }
}
