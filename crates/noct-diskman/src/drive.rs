use crate::{
    error::DiskManResult,
    structures::{Command, DriveType},
};

pub trait Drive {
    fn get_name(&self) -> &str;
    fn get_id(&self) -> &str;

    fn get_parent_disk_id(&self) -> Option<&str> {
        None
    }

    fn is_partition(&self) -> bool {
        self.get_parent_disk_id().is_some()
    }

    /// Gets the type of the drive.
    fn drive_type(&self) -> DriveType;

    /// Gets capacity of the drive in blocks.
    fn capacity(&self) -> Option<u64>;

    /// Gets block size of the drive in bytes.
    fn block_size(&self) -> Option<u32>;

    fn buffer_address_alignment(&self) -> usize;

    fn read(&mut self, location: u64, buffer: &mut [u8]) -> DiskManResult<u64>;
    fn write(&mut self, location: u64, buffer: &[u8]) -> DiskManResult<u64>;
    fn control(
        &mut self,
        command: Command,
        command_parameters: &[u8],
        data: &mut [u8],
    ) -> DiskManResult<()>;
}
