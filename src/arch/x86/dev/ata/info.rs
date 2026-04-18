use alloc::{boxed::Box, vec::Vec};

use crate::arch::x86::dev::ata::ATADrive;

pub struct ATADriveInfo {
    identity: Box<[u8]>
}

impl ATADriveInfo {
    pub fn raw(&self) -> &[u8] {
        &*self.identity
    }

    // Offset in bytes
    fn name_conv(&self, offset: usize, length: usize) -> &str {
        unsafe { str::from_utf8_unchecked(&self.identity[offset..offset+length]) }
    }

    pub fn model_name(&self) -> &str {
        self.name_conv(54, 40).trim()
    }

    pub fn firmware(&self) -> &str {
        self.name_conv(46, 8).trim()
    }

    pub fn serial(&self) -> &str {
        self.name_conv(20, 20).trim()
    }
}

impl TryFrom<Vec<u8>> for ATADriveInfo {
    type Error = ();

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        if value.len() != 512 {
            return Err(());
        }

        Ok(Self {
            identity: value.into_boxed_slice(),
        })
    }
}