use core::any::Any;

use alloc::vec;
use noct_cpuregs::CPURegisters;
use noct_interrupts::handler::register_interrupt_handler;
use noct_logger::qemu_log;
use x86::io::{inb, inw, outb};

use crate::arch::x86::dev::ata::{
    commands::{ATA_CMD_IDENTIFY, ATA_CMD_IDENTIFY_PACKET, ATA_CMD_PACKET},
    drive::ATAPhysicalDrive,
    error::{ATAError, ATAResult},
    flags::{ATA_SR_BSY, ATA_SR_DF, ATA_SR_DRQ, ATA_SR_ERR},
    info::ATADriveInfo,
    regs::{
        ATA_REG_ALTSTATUS, ATA_REG_COMMAND, ATA_REG_CONTROL, ATA_REG_DATA, ATA_REG_ERROR,
        ATA_REG_HDDEVSEL, ATA_REG_LBA0, ATA_REG_LBA1, ATA_REG_LBA2, ATA_REG_SECCOUNT0,
        ATA_REG_STATUS,
    },
};

pub mod commands;
pub mod drive;
pub mod error;
pub mod flags;
pub mod info;
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
        let status = unsafe { inb(io + ATA_REG_ALTSTATUS as u16) };

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

            return Ok(ATAPhysicalDrive {
                bus,
                drive,
                is_packet: true,
                identity: ide_buf.try_into().unwrap(),
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

        return Ok(ATAPhysicalDrive {
            bus,
            drive,
            is_packet: false,
            identity: ide_buf.try_into().unwrap(),
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

                    // if !drv.is_packet {
                    //     let mut buffer = vec![0u8; 512];
                        
                    //     {
                    //         drv.read48(0x0000_0000, 1, &mut buffer).unwrap();

                    //         qemu_log!("LBA0 = {:?}", unsafe { str::from_utf8_unchecked(&buffer) }.trim_end_matches('\0'));
                    //     }

                    //     {
                    //         buffer.fill(0);

                    //         drv.read48(0x0000_0001, 1, &mut buffer).unwrap();

                    //         qemu_log!("LBA1 = {:?}", unsafe { str::from_utf8_unchecked(&buffer) }.trim_end_matches('\0'));
                    //     }

                    //     {
                    //         buffer.fill(0);

                    //         let data = b"Hello, world!";

                    //         buffer[0..data.len()].copy_from_slice(data);

                    //         drv.write48(0x0000_0002, 1, &buffer).unwrap();
                    //     }
                    // }
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

    check_all();
}
