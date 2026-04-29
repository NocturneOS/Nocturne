use core::cell::Cell;

use noct_logger::qemu_log;
use noct_pci;
use noct_sync::pseudosync::PseudoSync;

use crate::arch::{
    mem::paging,
    x86::dev::ata::{
        ATADrive, commands::ATA_CMD_READ_DMA_EXT, drive::ATAPhysicalDrive, error::{ATAIOError, ATAIOResult}, io::ATAIO, regs::{
            ATA_REG_COMMAND, ATA_REG_HDDEVSEL, ATA_REG_LBA0, ATA_REG_LBA1, ATA_REG_LBA2,
            ATA_REG_SECCOUNT0,
        }
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
    pub(super) drive: &'a mut ATAPhysicalDrive,
}

impl ATAIO for ATADMA<'_> {
    fn read48(&mut self, lba: u64, output: &mut [u8]) -> ATAIOResult<()> {
        self::read48(self.drive, lba, output)
    }

    fn write48(&mut self, _lba: u64, _input: &[u8]) -> ATAIOResult<()> {
        Err(ATAIOError::UnsupportedOperation)
    }
}

pub fn read48(
    drv: &mut ATAPhysicalDrive,
    lba: u64,
    output: &mut [u8],
) -> ATAIOResult<()> {
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

    let pio = drv.pio_port();
    let dma = match drv.dma_io_port() {
        Some(port) => port,
        None => return Err(ATAIOError::DMAControllerNotInitialized),
    };
    let prdt = drv.prdt.as_mut().unwrap();

    prdt.clear();

    let buf_phys =
        paging::virt2phys(output.as_ptr().addr()).unwrap() + (output.as_ptr().addr() & 0xfff);

    qemu_log!("Phys: {buf_phys:x?}");

    prdt.set(
        0,
        buf_phys.try_into().unwrap(),
        output.len().try_into().unwrap(),
        true,
    )
    .unwrap();

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

            pio.offset(ATA_REG_HDDEVSEL).write8(0x40 + ((matches!(drv.drive, ATADrive::Slave) as u8) << 4));
            pio.offset(ATA_REG_SECCOUNT0).write8((controller_read_size >> 8) as u8);
            pio.offset(ATA_REG_LBA0).write8(lbas[3]);
            pio.offset(ATA_REG_LBA1).write8(lbas[4]);
            pio.offset(ATA_REG_LBA2).write8(lbas[5]);
            pio.offset(ATA_REG_SECCOUNT0).write8((controller_read_size & 0xff) as u8);
            pio.offset(ATA_REG_LBA0).write8(lbas[0]);
            pio.offset(ATA_REG_LBA1).write8(lbas[1]);
            pio.offset(ATA_REG_LBA2).write8(lbas[2]);
            pio.offset(ATA_REG_COMMAND).write8(ATA_CMD_READ_DMA_EXT);

            super::ide_poll_drq(pio.addr(), 65535).unwrap();

            x86::io::outb(dma.addr() + 0, 9);
        }

        super::ide_poll_bsy(pio.addr(), 65535).unwrap();

        let status_port = dma.offset(2);

        loop {
            let st = status_port.read8();

            if (st & 0x04) != 0 {
                break;
            }
        }

        dma.offset(0).write8(0);

        sector_count -= readsize;
        current_lba += readsize as u64;
    }

    Ok(())
}
