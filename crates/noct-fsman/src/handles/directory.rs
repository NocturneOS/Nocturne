use alloc::{string::String, sync::Arc, vec, vec::Vec};
use noct_io::error::Error;

use crate::{
    entity::EntityInfo,
};

pub struct DirectoryHandle {
    pub handle_id: u64,

    pub disk_id: Arc<String>,
}

impl DirectoryHandle {
    pub fn read(&mut self) -> noct_io::Result<DirectoryEntry> {
        let fs =
            crate::mount::get_handle(&self.disk_id).ok_or(Error::DiskNotRecognized)?;

        fs.readdir(self)
    }

    pub fn read_all(&mut self) -> noct_io::Result<Vec<DirectoryEntry>> {
        let fs =
            crate::mount::get_handle(&self.disk_id).ok_or(Error::DiskNotRecognized)?;

        let mut data = vec![];

        loop {
            let entry = fs.readdir(self);

            if let Err(Error::EndOfIterator) = entry {
                break;
            }

            data.push(entry?);
        }

        Ok(data)
    }
}

impl Drop for DirectoryHandle {
    fn drop(&mut self) {
        let Some(fs) = crate::mount::get_handle(&self.disk_id) else {
            return;
        };

        fs.closedir(self).ok();
    }
}

#[derive(Debug)]
pub struct DirectoryEntry {
    pub name: String,
    pub info: EntityInfo,
}
