use alloc::string::String;

use crate::{
    DRIVES,
    drive::Drive,
    error::{DiskManError, DiskManResult},
    structures::Command,
};

#[derive(Debug, Clone)]
pub struct Partition {
    pub(crate) parent_disk_name: String,
    pub(crate) parent_disk_id: String,

    // pub(crate) parition_number: usize,
    pub(crate) internal_id: String,

    /// Starting offset in bytes
    pub(crate) offset_start: u64,

    /// Ending offset in bytes
    pub(crate) offset_end: u64,
}

impl Partition {
    fn parent_operation<T>(&self, f: impl FnOnce(&dyn Drive) -> T) -> T {
        let binding = DRIVES.read();
        let parent_drive = binding
            .iter()
            .find(|x| x.read().get_id() == self.parent_disk_id)
            .expect("bug: failed to find a parent disk");

        f(parent_drive.read().as_ref())
    }

    fn parent_operation_mut<T>(&self, f: impl FnOnce(&mut dyn Drive) -> T) -> T {
        let binding = DRIVES.read();
        let parent_drive = binding
            .iter()
            .find(|x| x.read().get_id() == self.parent_disk_id)
            .expect("bug: failed to find a parent disk");

        f(parent_drive.write().as_mut())
    }
}

impl Drive for Partition {
    fn get_name(&self) -> &str {
        &self.parent_disk_name
    }

    fn get_id(&self) -> &str {
        &self.internal_id
    }

    fn get_parent_disk_id(&self) -> Option<&str> {
        Some(&self.parent_disk_id)
    }

    fn read(&mut self, location: u64, buffer: &mut [u8]) -> DiskManResult<i64> {
        if location >= self.offset_end {
            return Err(DiskManError::LocationOutOfBounds);
        }

        self.parent_operation_mut(|parent_drive| {
            parent_drive.read(self.offset_start + location, buffer)
        })
    }

    fn write(&mut self, location: u64, buffer: &[u8]) -> DiskManResult<i64> {
        self.parent_operation_mut(|parent_drive| {
            parent_drive.write(self.offset_start + location, buffer)
        })
    }

    fn control(
        &mut self,
        command: Command,
        command_parameters: &[u8],
        data: &mut [u8],
    ) -> DiskManResult<i64> {
        self.parent_operation_mut(|parent_drive| {
            parent_drive
                .control(command, command_parameters, data)
        })
    }

    fn buffer_address_alignment(&self) -> usize {
        self.parent_operation(|parent_drive| {
            parent_drive
                .buffer_address_alignment()
        })
    }
    
    fn drive_type(&self) -> crate::structures::DriveType {
        self.parent_operation(|parent_drive| {
            parent_drive
                .drive_type()
        })
    }
    
    fn capacity(&self) -> Option<u64> {
        Some(self.offset_end - self.offset_start)
    }
    
    fn block_size(&self) -> Option<u32> {
        self.parent_operation(|parent_drive| {
            parent_drive
                .block_size()
        })
    }
}
