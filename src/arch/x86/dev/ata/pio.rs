use x86::io::outb;

use crate::arch::x86::dev::ata::{
    ATADrive,
    commands::{ATA_CMD_CACHE_FLUSH_EXT, ATA_CMD_READ_PIO_EXT, ATA_CMD_WRITE_PIO_EXT},
    drive::ATAPhysicalDrive,
    error::{ATAIOError, ATAIOResult},
    ide_400ns_delay, ide_poll,
    io::ATAIO,
    regs::{
        ATA_REG_COMMAND, ATA_REG_DATA, ATA_REG_HDDEVSEL, ATA_REG_LBA0, ATA_REG_LBA1, ATA_REG_LBA2,
        ATA_REG_SECCOUNT0,
    },
};

pub struct ATAPIO<'drv> {
    pub(super) drive: &'drv mut ATAPhysicalDrive,
}

impl ATAIO for ATAPIO<'_> {
    fn read(&mut self, lba: u64, output: &mut [u8]) -> ATAIOResult<()> {
        let drv = &self.drive;

        if output.len() % drv.info().sector_size() != 0 {
            return Err(ATAIOError::InvalidBuffer);
        }

        let mut sector_count = output.len() / drv.info().sector_size();

        if sector_count * drv.info().sector_size() > output.len() {
            return Err(ATAIOError::InvalidBuffer);
        }

        if lba.checked_add(sector_count as _).is_none() {
            return Err(ATAIOError::InvalidLBA);
        }

        if (lba + sector_count as u64) > drv.info().max_lba() {
            return Err(ATAIOError::InvalidLBA);
        }

        let is_slave = drv.drive == ATADrive::Slave;

        let io = drv.pio_port();

        let max_sectors_per_transfer = 65536;
        let mut current_lba = lba;

        while sector_count != 0 {
            // In sectors.
            let readsize = if sector_count >= max_sectors_per_transfer {
                max_sectors_per_transfer
            } else {
                sector_count
            };

            let lbas = [
                (current_lba & 0xff) as u8,
                (current_lba >> 8) as u8,
                (current_lba >> 16) as u8,
                (current_lba >> 24) as u8,
                (current_lba >> 32) as u8,
                (current_lba >> 40) as u8,
            ];

            let controller_read_size = if readsize == max_sectors_per_transfer {
                0
            } else {
                readsize
            };

            unsafe {
                io.offset(ATA_REG_HDDEVSEL)
                    .write8(0x40 + ((is_slave as u8) << 4));
                io.offset(ATA_REG_SECCOUNT0)
                    .write8((controller_read_size >> 8) as u8);
                io.offset(ATA_REG_LBA0).write8(lbas[3]);
                io.offset(ATA_REG_LBA1).write8(lbas[4]);
                io.offset(ATA_REG_LBA2).write8(lbas[5]);
                io.offset(ATA_REG_SECCOUNT0)
                    .write8((controller_read_size & 0xff) as u8);
                io.offset(ATA_REG_LBA0).write8(lbas[0]);
                io.offset(ATA_REG_LBA1).write8(lbas[1]);
                io.offset(ATA_REG_LBA2).write8(lbas[2]);
                io.offset(ATA_REG_COMMAND).write8(ATA_CMD_READ_PIO_EXT);
            }

            let data = io.offset(ATA_REG_DATA);

            for sector in 0..readsize {
                ide_poll(io.addr()).map_err(ATAIOError::ControllerError)?;

                for i in (0..512).step_by(2) {
                    let word = unsafe { data.read16() };

                    output[(sector * 512) + i] = word as u8;
                    output[(sector * 512) + i + 1] = (word >> 8) as u8;
                }
            }

            sector_count -= readsize;
            current_lba += readsize as u64;
        }

        Ok(())
    }

    fn write(&mut self, lba: u64, input: &[u8]) -> ATAIOResult<()> {
        let drv = &self.drive;

        if input.len() % 512 != 0 {
            return Err(ATAIOError::InvalidBuffer);
        }

        let mut sector_count = input.len() / drv.info().sector_size();

        if sector_count * drv.info().sector_size() > input.len() {
            return Err(ATAIOError::InvalidBuffer);
        }

        if lba.checked_add(sector_count as _).is_none() {
            return Err(ATAIOError::InvalidLBA);
        }

        if (lba + sector_count as u64) > drv.info().max_lba() {
            return Err(ATAIOError::InvalidLBA);
        }

        let is_slave = drv.drive == ATADrive::Slave;

        let io = drv.pio_port();

        let max_sectors_per_transfer = 65536;
        let mut current_lba = lba;

        while sector_count != 0 {
            // In sectors.
            let writesize = if sector_count >= max_sectors_per_transfer {
                max_sectors_per_transfer
            } else {
                sector_count
            };

            let lbas = [
                (current_lba & 0xff) as u8,
                (current_lba >> 8) as u8,
                (current_lba >> 16) as u8,
                (current_lba >> 24) as u8,
                (current_lba >> 32) as u8,
                (current_lba >> 40) as u8,
            ];

            let controller_write_size = if writesize == max_sectors_per_transfer {
                0
            } else {
                writesize
            };

            unsafe {
                io.offset(ATA_REG_HDDEVSEL)
                    .write8(0x40 + ((is_slave as u8) << 4));
                io.offset(ATA_REG_SECCOUNT0)
                    .write8((controller_write_size >> 8) as u8);
                io.offset(ATA_REG_LBA0).write8(lbas[3]);
                io.offset(ATA_REG_LBA1).write8(lbas[4]);
                io.offset(ATA_REG_LBA2).write8(lbas[5]);
                io.offset(ATA_REG_SECCOUNT0)
                    .write8((controller_write_size & 0xff) as u8);
                io.offset(ATA_REG_LBA0).write8(lbas[0]);
                io.offset(ATA_REG_LBA1).write8(lbas[1]);
                io.offset(ATA_REG_LBA2).write8(lbas[2]);
                io.offset(ATA_REG_COMMAND).write8(ATA_CMD_WRITE_PIO_EXT);
            }

            let data = io.offset(ATA_REG_DATA);

            for _ in 0..writesize {
                ide_poll(io.addr()).map_err(ATAIOError::ControllerError)?;

                for v in input.chunks(2) {
                    ide_400ns_delay(io.addr());

                    let word = ((v[1] as u16) << 8) | v[0] as u16;

                    unsafe { data.write16(word) };
                }

                unsafe {
                    outb(io.addr() + ATA_REG_COMMAND as u16, ATA_CMD_CACHE_FLUSH_EXT);
                }

                ide_poll(io.addr()).map_err(ATAIOError::ControllerError)?;
            }

            sector_count -= writesize;
            current_lba += writesize as u64;
        }

        Ok(())
    }
}
