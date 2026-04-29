use x86::io::{inw, outb, outw};

use crate::arch::x86::{dev::ata::{
    ATABus, ATADrive, commands::{ATA_CMD_CACHE_FLUSH_EXT, ATA_CMD_READ_PIO_EXT, ATA_CMD_WRITE_PIO_EXT}, dma::DMA_IO_PORT, dma_prdt::PRDT, error::{ATAError, ATAIOError, ATAIOResult}, ide_400ns_delay, ide_poll, info::ATADriveInfo, io::ATAIO, regs::{ATA_REG_COMMAND, ATA_REG_DATA, ATA_REG_HDDEVSEL, ATA_REG_LBA0, ATA_REG_LBA1, ATA_REG_LBA2, ATA_REG_LBA3, ATA_REG_LBA4, ATA_REG_LBA5, ATA_REG_SECCOUNT0}
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
            super::dma::ATADMA { drive: self }.read48(lba, output)
        } else {
            super::pio::ATAPIO { drive: self }.read48(lba, output)
        }
    }

    pub fn write(&mut self, lba: u64, input: &[u8]) -> ATAIOResult<()> {
        if self.identity.is_dma_supported() {
            super::dma::ATADMA { drive: self }.write48(lba, input)
        } else {
            super::pio::ATAPIO { drive: self }.write48(lba, input)
        }
    }
}
