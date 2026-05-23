use core::alloc::Layout;

use alloc::{boxed::Box, vec};
use noct_cpu::CPURegisters;
use noct_interrupts::handler::register_interrupt_handler;
use noct_logger::qemu_log;
use x86::io::{inb, inw, outb};

use crate::arch::x86::dev::ata::{
    commands::{ATA_CMD_IDENTIFY, ATA_CMD_IDENTIFY_PACKET},
    dma_prdt::PRDT,
    drive::ATAPhysicalDrive,
    error::{ATAError, ATAResult},
    flags::{ATA_SR_BSY, ATA_SR_DF, ATA_SR_DRQ, ATA_SR_ERR},
    regs::{
        ATA_REG_ALTSTATUS, ATA_REG_COMMAND, ATA_REG_CONTROL, ATA_REG_DATA, ATA_REG_ERROR,
        ATA_REG_HDDEVSEL, ATA_REG_LBA0, ATA_REG_LBA1, ATA_REG_LBA2, ATA_REG_SECCOUNT0,
        ATA_REG_STATUS,
    },
};

pub mod commands;
pub mod dma;
pub mod dma_prdt;
pub mod drive;
pub mod error;
pub mod flags;
pub mod info;
pub mod io;
pub mod pio;
pub mod regs;

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum ATABus {
    Primary,
    Secondary,
}

impl ATABus {
    pub fn io(&self) -> u16 {
        match self {
            ATABus::Primary => 0x1F0,
            ATABus::Secondary => 0x170,
        }
    }

    pub fn dma_io_offset(&self) -> u16 {
        match self {
            ATABus::Primary => 0,
            ATABus::Secondary => 8,
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum ATADrive {
    Master,
    Slave,
}

fn soft_reset(io: u16) {
    unsafe { outb(io + ATA_REG_CONTROL as u16, 0x04) };

    ide_400ns_delay(io);

    unsafe { outb(io + ATA_REG_CONTROL as u16, 0) };
}

#[inline]
fn ide_select_drive(bus: ATABus, drive: ATADrive) {
    let io = bus.io();

    unsafe {
        outb(
            io + ATA_REG_HDDEVSEL as u16,
            0xA0 | (((drive == ATADrive::Slave) as u8) << 4),
        )
    };

    ide_400ns_delay(io);
}

fn ide_400ns_delay(io: u16) {
    unsafe {
        inb(io + ATA_REG_ALTSTATUS as u16);
        inb(io + ATA_REG_ALTSTATUS as u16);
        inb(io + ATA_REG_ALTSTATUS as u16);
        inb(io + ATA_REG_ALTSTATUS as u16);
    }
}

fn ide_poll_drq(io: u16, mut timeout: usize) -> ATAResult<()> {
    loop {
        let status = unsafe { inb(io + ATA_REG_STATUS as u16) };

        if (status & ATA_SR_DRQ) != 0 {
            return Ok(());
        } else if (status & ATA_SR_ERR) != 0 || (status & ATA_SR_DF) != 0 {
            return Err(unsafe { ATAError::ErrorSet(inb(io + ATA_REG_ERROR as u16)) });
        }

        if timeout == 0 {
            return Err(ATAError::TimedOut);
        }

        timeout -= 1;
    }
}

fn ide_poll_bsy(io: u16, mut timeout: usize) -> ATAResult<()> {
    loop {
        let status = unsafe { inb(io + ATA_REG_STATUS as u16) };

        if (status & ATA_SR_BSY) == 0 {
            return Ok(());
        } else if (status & ATA_SR_ERR) != 0 || (status & ATA_SR_DF) != 0 {
            return Err(unsafe { ATAError::ErrorSet(inb(io + ATA_REG_ERROR as u16)) });
        }

        if timeout == 0 {
            return Err(ATAError::TimedOut);
        }

        timeout -= 1;
    }
}

fn ide_poll(io: u16) -> ATAResult<()> {
    ide_400ns_delay(io);

    ide_poll_bsy(io, 65535)?;
    ide_poll_drq(io, 65535)?;

    Ok(())
}

fn identify(bus: ATABus, drive: ATADrive) -> ATAResult<ATAPhysicalDrive> {
    let io = bus.io();

    qemu_log!("Identifying {bus:?} {drive:?}");

    soft_reset(io);
    ide_select_drive(bus, drive);

    unsafe {
        outb(io + ATA_REG_SECCOUNT0 as u16, 0);
        outb(io + ATA_REG_LBA0 as u16, 0);
        outb(io + ATA_REG_LBA1 as u16, 0);
        outb(io + ATA_REG_LBA2 as u16, 0);
    }

    unsafe {
        outb(io + ATA_REG_COMMAND as u16, ATA_CMD_IDENTIFY);
    }

    ide_poll_bsy(io, 65535)?;

    let status = unsafe { inb(io + ATA_REG_STATUS as u16) };

    qemu_log!("Status: {}; Err: {}", status, status & ATA_SR_ERR);

    let mut ide_buf = vec![0u8; 512];

    // Check for ATAPI.
    // If error is set and following regs contain 0x01, 0x01, 0x14, 0xEB
    // then the device is a packet device,
    // and `IDENTIFY PACKET DEVICE` (0xA1) should be used.
    if (status & ATA_SR_ERR) != 0 {
        let seccount = unsafe { inb(io + ATA_REG_SECCOUNT0 as u16) };
        let lba_l = unsafe { inb(io + ATA_REG_LBA0 as u16) };
        let lba_m = unsafe { inb(io + ATA_REG_LBA1 as u16) };
        let lba_h = unsafe { inb(io + ATA_REG_LBA2 as u16) };

        if seccount == 0x01 && lba_l == 0x01 && lba_m == 0x14 && lba_h == 0xEB {
            qemu_log!("ATAPI!");

            unsafe { outb(io + ATA_REG_COMMAND as u16, ATA_CMD_IDENTIFY_PACKET) };

            for i in (0..512).step_by(2) {
                let word = unsafe { inw(io + ATA_REG_DATA as u16) };

                ide_buf[i] = ((word >> 8) & 0xff) as u8;
                ide_buf[i + 1] = (word & 0xff) as u8;
            }

            let identity: info::ATADriveInfo = ide_buf.try_into().unwrap();

            return Ok(ATAPhysicalDrive {
                bus,
                drive,
                is_packet: true,
                prdt: if identity.is_dma_supported() {
                    Some(PRDT::new())
                } else {
                    None
                },
                identity,
                diskman_id: Some(noct_diskman::generate_new_id("ata")),
            });
        }
    }

    if status != 0 {
        ide_poll(io)?;

        for i in (0..512).step_by(2) {
            let word = unsafe { inw(io + ATA_REG_DATA as u16) };

            ide_buf[i] = ((word >> 8) & 0xff) as u8;
            ide_buf[i + 1] = (word & 0xff) as u8;
        }

        let identity: info::ATADriveInfo = ide_buf.try_into().unwrap();

        return Ok(ATAPhysicalDrive {
            bus,
            drive,
            is_packet: false,
            prdt: if identity.is_dma_supported() {
                Some(PRDT::new())
            } else {
                None
            },
            identity: identity,
            diskman_id: Some(noct_diskman::generate_new_id("ata")),
        });
    }

    Err(ATAError::NoDrive)
}

fn check_all() {
    for bus in [ATABus::Primary, ATABus::Secondary] {
        for drive in [ATADrive::Master, ATADrive::Slave] {
            let result = identify(bus, drive);

            match result {
                Ok(drv) => {
                    qemu_log!("{bus:?} {drive:?} => OK!");

                    qemu_log!(
                        "Model: {:?}; FW: {:?}; Serial: {:?}",
                        drv.info().model_name(),
                        drv.info().firmware(),
                        drv.info().serial()
                    );

                    qemu_log!("Sector size: {:?}", drv.info().sector_size());

                    // FIXME: Remove that condition when I make Packet ATA work.
                    if !drv.info().is_removable_media_device() {
                        noct_diskman::register_drive(Box::new(drv)).ok();
                    }
                }
                Err(e) => {
                    qemu_log!("{bus:?} {drive:?} => Err({e:?})!");
                }
            }
        }
    }
}

fn primary_bus_irq(_regs: &mut CPURegisters) {
    unsafe { inb(ATABus::Primary.io() + ATA_REG_STATUS as u16) };
}

fn secondary_bus_irq(_regs: &mut CPURegisters) {
    unsafe { inb(ATABus::Secondary.io() + ATA_REG_STATUS as u16) };
}

pub fn init() {
    register_interrupt_handler(0x20 + 14, primary_bus_irq);
    register_interrupt_handler(0x20 + 15, secondary_bus_irq);

    dma::init().unwrap();

    check_all();
}
