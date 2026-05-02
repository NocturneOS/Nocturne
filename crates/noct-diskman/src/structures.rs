use num_derive::FromPrimitive;
use num_traits::FromPrimitive;

use crate::{error::DiskManResult, view::DiskView};

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
}