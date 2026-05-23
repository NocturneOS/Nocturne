use alloc::string::String;
use noct_diskman::{error::DiskManResult, structures::Command};
use noct_logger::qemu_log;

use crate::arch::x86::{
    dev::ata::{
        ATABus, ATADrive,
        dma::DMA_IO_PORT,
        dma_prdt::PRDT,
        error::{ATAIOError, ATAIOResult},
        info::ATADriveInfo,
        io::ATAIO,
    },
    io::IOPort,
};

pub struct ATAPhysicalDrive {
    pub(super) bus: ATABus,
    pub(super) drive: ATADrive,
    pub(super) is_packet: bool,
    pub(super) identity: ATADriveInfo,
    pub(super) prdt: Option<PRDT>,
    pub(super) diskman_id: Option<String>,
}

impl ATAPhysicalDrive {
    pub fn info(&self) -> &ATADriveInfo {
        &self.identity
    }

    pub fn pio_port(&self) -> IOPort {
        IOPort::new(self.bus.io())
    }

    pub fn dma_io_port(&self) -> Option<IOPort> {
        let offset = self.bus.dma_io_offset();

        DMA_IO_PORT
            .get()
            .get()
            .map(|base| IOPort::new(base + offset))
    }

    pub fn read(&mut self, lba: u64, output: &mut [u8]) -> ATAIOResult<()> {
        // qemu_log!("Reading from drive {} at LBA {} with length {} bytes", self.diskman_id.as_deref().unwrap_or("<unknown>"), lba, output.len());

        if self.identity.is_dma_supported() {
            if self.identity.is_removable_media_device() {
                todo!("DMA reading for removable media devices is not yet implemented");
            }

            super::dma::ATADMA { drive: self }.read48(lba, output)
        } else {
            if self.identity.is_removable_media_device() {
                todo!("PIO reading for removable media devices is not yet implemented");
            }

            super::pio::ATAPIO { drive: self }.read48(lba, output)
        }
    }

    pub fn write(&mut self, lba: u64, input: &[u8]) -> ATAIOResult<()> {
        qemu_log!(
            "Writing to drive {} at LBA {} with length {} bytes",
            self.diskman_id.as_deref().unwrap_or("<unknown>"),
            lba,
            input.len()
        );

        if self.identity.is_dma_supported() {
            // Direct writing to removable media devices is not supported,
            // because to write on a removable medium requires user making the TOC,
            // other calculations, performing power calibration (OPC), etc. which are not implemented yet.
            if self.identity.is_removable_media_device() {
                return Err(ATAIOError::UnsupportedOperation);
            }

            super::dma::ATADMA { drive: self }.write48(lba, input)
        } else {
            // See comment above.
            if self.identity.is_removable_media_device() {
                return Err(ATAIOError::UnsupportedOperation);
            }

            super::pio::ATAPIO { drive: self }.write48(lba, input)
        }
    }
}

impl noct_diskman::drive::Drive for ATAPhysicalDrive {
    fn get_name(&self) -> &str {
        "ata"
    }

    fn get_id(&self) -> &str {
        self.diskman_id.as_deref().unwrap()
    }

    fn read(&mut self, location: u64, buffer: &mut [u8]) -> DiskManResult<u64> {
        self.read(location, buffer)
            .map(|_| buffer.len() as _)
            .map_err(|e| panic!("Error: {e:?}"))
    }

    fn write(&mut self, location: u64, buffer: &[u8]) -> DiskManResult<u64> {
        self.write(location, buffer)
            .map(|_| buffer.len() as _)
            .map_err(|e| panic!("Error: {e:?}"))
    }

    fn control(
        &mut self,
        command: Command,
        command_parameters: &[u8],
        data: &mut [u8],
    ) -> DiskManResult<()> {
        match command {
            cmd => todo!("Unimplemented control command for ATA (issued: {cmd:?})"),
        }
    }

    fn buffer_address_alignment(&self) -> usize {
        1
    }

    fn drive_type(&self) -> noct_diskman::structures::DriveType {
        if self.info().is_removable_media_device() {
            noct_diskman::structures::DriveType::RemovableMedia
        } else {
            noct_diskman::structures::DriveType::HardDrive
        }
    }

    fn capacity(&self) -> Option<u64> {
        Some(self.info().max_lba())
    }

    fn block_size(&self) -> Option<u32> {
        Some(self.info().sector_size() as _)
    }
}
