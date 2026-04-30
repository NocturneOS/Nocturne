use num_derive::FromPrimitive;
use num_traits::FromPrimitive;

#[repr(u32)]
#[derive(FromPrimitive, Debug, Clone, Copy)]
pub enum DriveType {
    Unknown = 0xff,

    HardDrive = 0x00,
    RemovableMedia = 0x01,
}

#[repr(u32)]
#[derive(FromPrimitive, Debug, Clone, Copy)]
pub enum MediumStatus {
    Offline = 0x00,
    Loading = 0x01,
    Online = 0x02,
}

/// Command that can be sent by using `diskman_command` function.
#[repr(u32)]
#[derive(FromPrimitive, Debug, Clone, Copy, PartialEq)]
pub enum Command {
    Eject = 0x00,
    GetMediumStatus = 0x01,
    // Needs a 4-byte slice.
    // It contains a u32 value representing the drive type, which is the same as the `DriveType` enum.
    GetDriveType = 0x02,
    // Needs a 12-byte slice.
    // [0..8] are a u64 value representing the capacity of the drive in sectors,
    // [8..12] are a u32 value representing the block size of the drive in bytes.
    GetMediumCapacity = 0x03,
}

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
    fn get_type(&mut self) -> DriveType {
        let mut data = [0u8; 4];

        self.control(Command::GetDriveType, &[], &mut data);

        DriveType::from_u32(u32::from_ne_bytes(data)).unwrap_or(DriveType::Unknown)
    }

    /// Gets capacity of the drive in blocks.
    fn get_capacity(&mut self) -> Option<u64> {
        let mut data = [0u8; 12];

        self.control(Command::GetMediumCapacity, &[], &mut data);

        match u64::from_ne_bytes(data[..8].try_into().unwrap()) {
            0 => None,
            n => Some(n),
        }
    }

    /// Gets block size of the drive in bytes.
    fn get_block_size(&mut self) -> Option<u32> {
        let mut data = [0u8; 12];

        self.control(Command::GetMediumCapacity, &[], &mut data);

        match u32::from_ne_bytes(data[8..].try_into().unwrap()) {
            0 => None,
            n => Some(n),
        }
    }

    fn read(&mut self, location: u64, buffer: &mut [u8]) -> i64;
    fn write(&mut self, location: u64, buffer: &[u8]) -> i64;
    fn control(&mut self, command: Command, command_parameters: &[u8], data: &mut [u8]) -> i64;
}
