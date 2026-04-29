use crate::arch::x86::{dev::ata::{
    ATABus, ATADrive, dma::DMA_IO_PORT, dma_prdt::PRDT, error::{ATAIOError, ATAIOResult}, info::ATADriveInfo, io::ATAIO
}, io::IOPort};

pub struct ATAPhysicalDrive {
    pub(super) bus: ATABus,
    pub(super) drive: ATADrive,
    pub(super) is_packet: bool,
    pub(super) identity: ATADriveInfo,
    pub(super) prdt: Option<PRDT>
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
        
        DMA_IO_PORT.get().get().map(|base| IOPort::new(base + offset))
    }

    pub fn read(&mut self, lba: u64, output: &mut [u8]) -> ATAIOResult<()> {
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
