use core::{alloc::Layout, cell::Cell};

use noct_logger::qemu_log;
use noct_pci;
use noct_sync::pseudosync::PseudoSync;

use crate::arch::{mem::paging, x86::dev::ata::{ATADrive, commands::{ATA_CMD_READ_DMA_EXT, ATA_CMD_READ_PIO_EXT}, drive::ATAPhysicalDrive, regs::{ATA_REG_COMMAND, ATA_REG_HDDEVSEL, ATA_REG_LBA0, ATA_REG_LBA1, ATA_REG_LBA2, ATA_REG_SECCOUNT0, ATA_REG_STATUS}}};

const PCI_VENDOR: u16 = 0x8086;
const PCI_DEVICE: u16 = 0x7010;

static DMA_IO_PORT: PseudoSync<Cell<Option<u16>>> = PseudoSync::new(Cell::new(None));

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

pub fn test_read_sector(drv: &mut ATAPhysicalDrive, lba: u64, buffer: &mut [u8]) {
    let pio = drv.bus.io();
    let dma = DMA_IO_PORT.get().get().unwrap() + drv.bus.dma_io_offset();
    let prdt = drv.prdt.as_mut().unwrap();

    prdt.clear();

    let buf_phys = paging::virt2phys(buffer.as_ptr().addr()).unwrap() + (buffer.as_ptr().addr() & 0xfff);

    qemu_log!("Phys: {buf_phys:x?}");

    prdt.set(
        0,
        buf_phys.try_into().unwrap(),
        buffer.len().try_into().unwrap(),
        true,
    ).unwrap();

    let lbas = [
        (lba & 0xff) as u8,
        (lba >> 8) as u8,
        (lba >> 16) as u8,
        (lba >> 24) as u8,
        (lba >> 32) as u8,
        (lba >> 40) as u8,
    ];

    unsafe {
        x86::io::outb(dma + 0, 8);
        x86::io::outb(dma + 2, 6);
        x86::io::outl(dma + 4, prdt.phys());

        x86::io::outb(
            pio + ATA_REG_HDDEVSEL as u16,
            0x40 + ((matches!(drv.drive, ATADrive::Slave) as u8) << 4),
        );
        x86::io::outb(pio + ATA_REG_SECCOUNT0 as u16, 0 as u8);
        x86::io::outb(pio + ATA_REG_LBA0 as u16, lbas[3]);
        x86::io::outb(pio + ATA_REG_LBA1 as u16, lbas[4]);
        x86::io::outb(pio + ATA_REG_LBA2 as u16, lbas[5]);
        x86::io::outb(pio + ATA_REG_SECCOUNT0 as u16, 1 as u8);
        x86::io::outb(pio + ATA_REG_LBA0 as u16, lbas[0]);
        x86::io::outb(pio + ATA_REG_LBA1 as u16, lbas[1]);
        x86::io::outb(pio + ATA_REG_LBA2 as u16, lbas[2]);
        x86::io::outb(pio + ATA_REG_COMMAND as u16, ATA_CMD_READ_DMA_EXT);

        super::ide_poll_drq(pio, 65535).unwrap();

        x86::io::outb(dma + 0, 9);
    }

    super::ide_poll_bsy(pio, 65535).unwrap();

    loop {
        let st = unsafe { x86::io::inb(dma + 2) };

        if (st & 0x04) != 0 {
            break;
        }
    }

    unsafe {
        x86::io::outb(dma + 0, 0);
    }
}
