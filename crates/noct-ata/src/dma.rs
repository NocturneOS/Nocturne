use core::cell::Cell;

use noct_diskman::drive::Drive;
use noct_logger::qemu_log;
use noct_sync::pseudosync::PseudoSync;

use super::dma_prdt::Prdt;
use crate::{
        ATADrive, atapi::send_scsi, commands::{ATA_CMD_READ_DMA_EXT, ATA_CMD_WRITE_DMA_EXT, ATAPI_CMD_READ}, drive::AtaPhysicalDrive, error::{AtaIoError, ATAIOResult}, ide_poll, io::ATAIO, regs::{
            ATA_REG_COMMAND, ATA_REG_HDDEVSEL, ATA_REG_LBA0, ATA_REG_LBA1, ATA_REG_LBA2,
            ATA_REG_SECCOUNT0,
    },
};

const PCI_VENDOR: u16 = 0x8086;
const PCI_DEVICE: u16 = 0x7010;

pub(super) static DMA_IO_PORT: PseudoSync<Cell<Option<u16>>> = PseudoSync::new(Cell::new(None));

pub fn init() -> Result<(), ()> {
    let device = match noct_pci::find_device(PCI_VENDOR, PCI_DEVICE) {
        Some(dev) => dev,
        None => {
            qemu_log!("Cannot find ATA DMA controller by PCI.");
            return Err(());
        }
    };

    qemu_log!("Found ATA DMA controller!");

    device.enable_bus_mastering();

    let bar4 = device.read_bar(4).ok_or(())?;

    qemu_log!("BAR4: {bar4:08x?}");

    unsafe {
        DMA_IO_PORT
            .get_mut()
            .set(Some(bar4.address.try_into().unwrap()))
    };

    Ok(())
}

pub struct ATADMA<'a> {
    pub(super) drive: &'a mut AtaPhysicalDrive,
}

impl ATAIO for ATADMA<'_> {
    fn read(&mut self, lba: u64, output: &mut [u8]) -> ATAIOResult<()> {
        self::read48(self.drive, lba, output)
    }

    fn write(&mut self, lba: u64, input: &[u8]) -> ATAIOResult<()> {
        self::write48(self.drive, lba, input)
    }
}

pub fn fill_prdt(prdt: &mut Prdt, buffer: &[u8]) {
    prdt.clear();

    // TODO: Improvement: Make them extents
    let chunk_size = noct_mem::get_page_size();
    let chunks_count = buffer.chunks(chunk_size).count();

    for (i, chunk) in buffer.chunks(chunk_size).enumerate() {
        let buf_virt = chunk.as_ptr().addr();
        let buf_phys = noct_mem::paging::virt2phys_precise(buf_virt).unwrap();

        // qemu_log!("V{buf_virt:x?} -> P{buf_phys:x?}");

        prdt.set(
            i,
            buf_phys.try_into().unwrap(),
            chunk.len().try_into().unwrap(),
            chunks_count == i + 1,
        )
        .unwrap();
    }

    // for i in 0..chunks_count {
    //     let entry = prdt.get(i).unwrap();

    //     qemu_log!("PRDT {i}: {:#010x}: {:#06x}; LAST: {}", entry.buffer_phys(), entry.transfer_size(), entry.is_last());
    // }
}

pub fn read48(drv: &mut AtaPhysicalDrive, lba: u64, output: &mut [u8]) -> ATAIOResult<()> {
    if output.len() % drv.info().sector_size() != 0 {
        return Err(AtaIoError::InvalidBuffer);
    }

    let mut sector_count = output.len() / drv.info().sector_size();

    if sector_count * drv.info().sector_size() > output.len() {
        return Err(AtaIoError::InvalidBuffer);
    }

    if lba.checked_add(sector_count as _).is_none() {
        return Err(AtaIoError::InvalidLBA);
    }

    if (lba + sector_count as u64) > drv.info().max_lba() {
        return Err(AtaIoError::InvalidLBA);
    }

    let pio = drv.pio_port();
    let dma = match drv.dma_io_port() {
        Some(port) => port,
        None => return Err(AtaIoError::DMAControllerNotInitialized),
    };
    let prdt = drv.prdt.as_mut().unwrap();

    fill_prdt(prdt, output);

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
            dma.offset(0).write8(8);
            dma.offset(2).write8(6);
            dma.offset(4).write32(prdt.phys());

            pio.offset(ATA_REG_HDDEVSEL)
                .write8(0x40 + ((matches!(drv.drive, ATADrive::Slave) as u8) << 4));
            pio.offset(ATA_REG_SECCOUNT0)
                .write8((controller_read_size >> 8) as u8);
            pio.offset(ATA_REG_LBA0).write8(lbas[3]);
            pio.offset(ATA_REG_LBA1).write8(lbas[4]);
            pio.offset(ATA_REG_LBA2).write8(lbas[5]);
            pio.offset(ATA_REG_SECCOUNT0)
                .write8((controller_read_size & 0xff) as u8);
            pio.offset(ATA_REG_LBA0).write8(lbas[0]);
            pio.offset(ATA_REG_LBA1).write8(lbas[1]);
            pio.offset(ATA_REG_LBA2).write8(lbas[2]);
            pio.offset(ATA_REG_COMMAND).write8(ATA_CMD_READ_DMA_EXT);

            super::ide_poll_drq(pio.addr(), 65535).unwrap();

            dma.write8(9);
        }

        super::ide_poll_bsy(pio.addr(), 65535).unwrap();

        let status_port = dma.offset(2);

        loop {
            let st = unsafe { status_port.read8() };

            if (st & 0x04) != 0 {
                break;
            }
        }

        unsafe { dma.write8(0) };

        sector_count -= readsize;
        current_lba += readsize as u64;
    }

    Ok(())
}

pub fn write48(drv: &mut AtaPhysicalDrive, lba: u64, input: &[u8]) -> ATAIOResult<()> {
    if input.len() % drv.info().sector_size() != 0 {
        return Err(AtaIoError::InvalidBuffer);
    }

    let mut sector_count = input.len() / drv.info().sector_size();

    if sector_count * drv.info().sector_size() > input.len() {
        return Err(AtaIoError::InvalidBuffer);
    }

    if lba.checked_add(sector_count as _).is_none() {
        return Err(AtaIoError::InvalidLBA);
    }

    if (lba + sector_count as u64) > drv.info().max_lba() {
        return Err(AtaIoError::InvalidLBA);
    }

    let pio = drv.pio_port();
    let dma = match drv.dma_io_port() {
        Some(port) => port,
        None => return Err(AtaIoError::DMAControllerNotInitialized),
    };
    let prdt = drv.prdt.as_mut().unwrap();

    fill_prdt(prdt, input);

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
            dma.offset(0).write8(0);
            dma.offset(2).write8(6);
            dma.offset(4).write32(prdt.phys());

            pio.offset(ATA_REG_HDDEVSEL)
                .write8(0x40 + ((matches!(drv.drive, ATADrive::Slave) as u8) << 4));
            pio.offset(ATA_REG_SECCOUNT0)
                .write8((controller_read_size >> 8) as u8);
            pio.offset(ATA_REG_LBA0).write8(lbas[3]);
            pio.offset(ATA_REG_LBA1).write8(lbas[4]);
            pio.offset(ATA_REG_LBA2).write8(lbas[5]);
            pio.offset(ATA_REG_SECCOUNT0)
                .write8((controller_read_size & 0xff) as u8);
            pio.offset(ATA_REG_LBA0).write8(lbas[0]);
            pio.offset(ATA_REG_LBA1).write8(lbas[1]);
            pio.offset(ATA_REG_LBA2).write8(lbas[2]);
            pio.offset(ATA_REG_COMMAND).write8(ATA_CMD_WRITE_DMA_EXT);

            super::ide_poll_drq(pio.addr(), 65535).unwrap();

            dma.write8(1);
        }

        super::ide_poll_bsy(pio.addr(), 65535).unwrap();

        let status_port = dma.offset(2);

        loop {
            let st = unsafe { status_port.read8() };

            if (st & 0x04) != 0 {
                break;
            }
        }

        unsafe { dma.offset(0).write8(0) };

        sector_count -= readsize;
        current_lba += readsize as u64;
    }

    Ok(())
}