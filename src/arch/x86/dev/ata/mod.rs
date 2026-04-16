use x86::io::{inb, outb};

use crate::arch::x86::dev::ata::{flags::{ATA_SR_BSY, ATA_SR_DF, ATA_SR_DRQ, ATA_SR_ERR}, regs::{ATA_REG_ALTSTATUS, ATA_REG_CONTROL, ATA_REG_HDDEVSEL, ATA_REG_STATUS}};

pub mod flags;
pub mod regs;

pub const ATA_PRIMARY_IO: u16 = 0x1F0;
pub const ATA_SECONDARY_IO: u16 = 0x170;

pub enum ATABus {
    Primary,
    Secondary,
}

fn soft_reset(io: u16) {
    unsafe { outb(io + ATA_REG_CONTROL as u16, 0x04) };
    ide_400ns_delay(io);
    unsafe { outb(io + ATA_REG_CONTROL as u16, 0) };
}

#[inline]
fn ide_select_drive(bus: ATABus, slave: bool) {
    match bus {
        ATABus::Primary => unsafe {
            outb(
                ATA_PRIMARY_IO + ATA_REG_HDDEVSEL as u16,
                0xA0 | ((slave as u8) << 4) ,
            )
        },
        ATABus::Secondary => unsafe {
            outb(
                ATA_SECONDARY_IO + ATA_REG_HDDEVSEL as u16,
                0xA0 | ((slave as u8) << 4) ,
            )
        },
    }
}

fn ide_400ns_delay(io: u16) {
    unsafe {
        inb(io + ATA_REG_ALTSTATUS as u16);
        inb(io + ATA_REG_ALTSTATUS as u16);
        inb(io + ATA_REG_ALTSTATUS as u16);
        inb(io + ATA_REG_ALTSTATUS as u16);
    }
}

fn ide_poll_drq(io: u16) -> bool {
    loop {
        let status = unsafe { inb(io + ATA_REG_ALTSTATUS as u16) };
        if (status & ATA_SR_DRQ) != 0 {
            return true;
        } else if (status & ATA_SR_ERR) != 0 || (status & ATA_SR_DF) != 0 {
            return false;
        }
    }
}

fn ide_poll_bsy(io: u16) -> bool {
    loop {
        let status = unsafe { inb(io + ATA_REG_STATUS as u16) };
        if (status & ATA_SR_BSY) == 0 {
            return true;
        } else if (status & ATA_SR_ERR) != 0 || (status & ATA_SR_DF) != 0  {
            return false;
        }
    }
}
