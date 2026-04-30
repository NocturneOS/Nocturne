use alloc::string::String;

use crate::{
    DRIVES,
    structures::{Command, Drive},
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

    fn read(&mut self, location: u64, buffer: &mut [u8]) -> i64 {
        let binding = DRIVES.read();
        let parent_drive = binding
            .iter()
            .find(|x| x.read().get_id() == self.parent_disk_id)
            .expect("bug: failed to find a parent disk");

        if location >= self.offset_end {
            return 0;
        }

        parent_drive
            .write()
            .read(self.offset_start + location, buffer)
    }

    fn write(&mut self, location: u64, buffer: &[u8]) -> i64 {
        let binding = DRIVES.read();
        let parent_drive = binding
            .iter()
            .find(|x| x.read().get_id() == self.parent_disk_id)
            .expect("bug: failed to find a parent disk");

        if location >= self.offset_end {
            return 0;
        }

        parent_drive
            .write()
            .write(self.offset_start + location, buffer)
    }

    fn control(&mut self, command: Command, command_parameters: &[u8], data: &mut [u8]) -> i64 {
        let binding = DRIVES.read();
        let parent_drive = binding
            .iter()
            .find(|x| x.read().get_id() == self.parent_disk_id)
            .expect("bug: failed to find a parent disk");

        if command == Command::GetMediumCapacity {
            let bs = parent_drive.write().get_block_size().unwrap_or(1);
            let sects = self.offset_end - self.offset_start;

            let sects: [u8; 8] = u64::to_le_bytes(sects);
            let bs: [u8; 4] = u32::to_le_bytes(bs);

            data[..8].copy_from_slice(&sects);
            data[8..12].copy_from_slice(&bs);

            return 0;
        }

        parent_drive
            .write()
            .control(command, command_parameters, data)
    }
}
