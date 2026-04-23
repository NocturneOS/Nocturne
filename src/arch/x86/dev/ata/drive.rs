use x86::io::{inw, outb, outw};

use crate::arch::x86::dev::ata::{
    ATABus, ATADrive, commands::{ATA_CMD_CACHE_FLUSH_EXT, ATA_CMD_READ_PIO_EXT, ATA_CMD_WRITE_PIO_EXT}, dma_prdt::PRDT, error::{ATAError, ATAIOError, ATAIOResult}, ide_400ns_delay, ide_poll, info::ATADriveInfo, regs::{ATA_REG_COMMAND, ATA_REG_DATA, ATA_REG_HDDEVSEL, ATA_REG_LBA0, ATA_REG_LBA1, ATA_REG_LBA2, ATA_REG_LBA3, ATA_REG_LBA4, ATA_REG_LBA5, ATA_REG_SECCOUNT0}
};

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

    pub fn read48(&self, lba: u64, mut sector_count: usize, output: &mut [u8]) -> ATAIOResult<()> {
        if output.len() % 512 != 0 {
            return Err(ATAIOError::InvalidBuffer);
        }

        if sector_count * self.info().sector_size() > output.len() {
            return Err(ATAIOError::InvalidBuffer);
        }

        if lba.checked_add(sector_count as _).is_none() {
            return Err(ATAIOError::InvalidLBA);
        }

        if (lba + sector_count as u64) > self.info().max_lba() {
            return Err(ATAIOError::InvalidLBA);
        }

        let is_slave = self.drive == ATADrive::Slave;

        let max_sectors_per_transfer = 65536;

        while sector_count != 0 {
            // In sectors.
            let readsize = if sector_count >= max_sectors_per_transfer {
                max_sectors_per_transfer
            } else {
                sector_count
            };

            let lbas = [
                (lba & 0xff) as u8,
                (lba >> 8) as u8,
                (lba >> 16) as u8,
                (lba >> 24) as u8,
                (lba >> 32) as u8,
                (lba >> 40) as u8,
            ];

            let controller_read_size = if readsize == max_sectors_per_transfer { 0 } else { readsize };

            unsafe {
                outb(
                    self.bus.io() + ATA_REG_HDDEVSEL as u16,
                    0x40 + ((is_slave as u8) << 4),
                );
                outb(self.bus.io() + ATA_REG_SECCOUNT0 as u16, (controller_read_size >> 8) as u8);
                outb(self.bus.io() + ATA_REG_LBA0 as u16, lbas[3]);
                outb(self.bus.io() + ATA_REG_LBA1 as u16, lbas[4]);
                outb(self.bus.io() + ATA_REG_LBA2 as u16, lbas[5]);
                outb(self.bus.io() + ATA_REG_SECCOUNT0 as u16, (controller_read_size & 0xff) as u8);
                outb(self.bus.io() + ATA_REG_LBA0 as u16, lbas[0]);
                outb(self.bus.io() + ATA_REG_LBA1 as u16, lbas[1]);
                outb(self.bus.io() + ATA_REG_LBA2 as u16, lbas[2]);
                outb(self.bus.io() + ATA_REG_COMMAND as u16, ATA_CMD_READ_PIO_EXT);
            };

            for sector in 0..readsize {
                ide_poll(self.bus.io()).map_err(ATAIOError::ControllerError)?;

                for i in (0..512).step_by(2) {
                    let word = unsafe { inw(self.bus.io() + ATA_REG_DATA as u16) };

                    output[(sector * 512) + i] = word as u8;
                    output[(sector * 512) + i + 1] = (word >> 8) as u8;
                }
            }

            sector_count -= readsize;
        }

        Ok(())
    }

    pub fn write48(&self, lba: u64, mut sector_count: usize, input: &[u8]) -> ATAIOResult<()> {
        if input.len() % 512 != 0 {
            return Err(ATAIOError::InvalidBuffer);
        }

        if sector_count * self.info().sector_size() > input.len() {
            return Err(ATAIOError::InvalidBuffer);
        }

        if lba.checked_add(sector_count as _).is_none() {
            return Err(ATAIOError::InvalidLBA);
        }

        if (lba + sector_count as u64) > self.info().max_lba() {
            return Err(ATAIOError::InvalidLBA);
        }

        let is_slave = self.drive == ATADrive::Slave;

        let max_sectors_per_transfer = 65536;

        while sector_count != 0 {
            // In sectors.
            let writesize = if sector_count >= max_sectors_per_transfer {
                max_sectors_per_transfer
            } else {
                sector_count
            };

            let lbas = [
                (lba & 0xff) as u8,
                (lba >> 8) as u8,
                (lba >> 16) as u8,
                (lba >> 24) as u8,
                (lba >> 32) as u8,
                (lba >> 40) as u8,
            ];

            let controller_write_size = if writesize == max_sectors_per_transfer { 0 } else { writesize };

            unsafe {
                outb(
                    self.bus.io() + ATA_REG_HDDEVSEL as u16,
                    0x40 + ((is_slave as u8) << 4),
                );
                outb(self.bus.io() + ATA_REG_SECCOUNT0 as u16, (controller_write_size >> 8) as u8);
                outb(self.bus.io() + ATA_REG_LBA0 as u16, lbas[3]);
                outb(self.bus.io() + ATA_REG_LBA1 as u16, lbas[4]);
                outb(self.bus.io() + ATA_REG_LBA2 as u16, lbas[5]);
                outb(self.bus.io() + ATA_REG_SECCOUNT0 as u16, (controller_write_size & 0xff) as u8);
                outb(self.bus.io() + ATA_REG_LBA0 as u16, lbas[0]);
                outb(self.bus.io() + ATA_REG_LBA1 as u16, lbas[1]);
                outb(self.bus.io() + ATA_REG_LBA2 as u16, lbas[2]);
                outb(self.bus.io() + ATA_REG_COMMAND as u16, ATA_CMD_WRITE_PIO_EXT);
            };

            for _ in 0..writesize {
                ide_poll(self.bus.io()).map_err(ATAIOError::ControllerError)?;

                for v in input.chunks(2) {
                    ide_400ns_delay(self.bus.io());

                    let word = ((v[1] as u16) << 8) | v[0] as u16;

                    unsafe { outw(self.bus.io() + ATA_REG_DATA as u16, word) };
                }
            }

            unsafe {
                outb(self.bus.io() + ATA_REG_COMMAND as u16, ATA_CMD_CACHE_FLUSH_EXT);
            }

            ide_poll(self.bus.io()).map_err(ATAIOError::ControllerError)?;

            sector_count -= writesize;
        }

        Ok(())
    }
}
