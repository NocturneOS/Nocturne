use alloc::boxed::Box;

use crate::arch::x86::dev::ata::info::ATADriveInfo;

pub struct ATAPhysicalDrive {
    pub(in super) is_packet: bool,
    pub(in super) identity: ATADriveInfo
}

