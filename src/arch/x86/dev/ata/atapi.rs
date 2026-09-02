use alloc::vec;
use noct_diskman::drive::Drive;

use crate::arch::x86::dev::ata::{
    commands::{ATA_CMD_PACKET, ATAPI_CMD_READ, ATAPI_CMD_READ_CAPACITY, ATAPI_CMD_START_STOP},
    drive::ATAPhysicalDrive,
    error::{ATAIOError, ATAIOResult, ATAResult},
    ide_400ns_delay, ide_poll, ide_select_drive,
    regs::{ATA_REG_COMMAND, ATA_REG_DATA, ATA_REG_ERROR, ATA_REG_LBA1, ATA_REG_LBA2},
};

pub fn send_scsi(drive: &ATAPhysicalDrive, lba: u16, command: &[u16]) -> ATAResult<()> {
    assert!(command.len() <= 16);

    ide_select_drive(drive.bus, drive.drive);

    let port = drive.pio_port();

    unsafe {
        port.offset(ATA_REG_ERROR).write8(0);
        port.offset(ATA_REG_LBA1).write8((lba & 0xff) as _);
        port.offset(ATA_REG_LBA2).write8(((lba >> 8) & 0xff) as _);
        port.offset(ATA_REG_COMMAND).write8(ATA_CMD_PACKET);
    }

    ide_400ns_delay(drive.bus.io());

    ide_poll(drive.bus.io())?;

    unsafe { port.offset(ATA_REG_DATA).write16_bulk(command) };

    Ok(())
}

pub fn send_scsi8(drive: &ATAPhysicalDrive, lba: u16, command: &[u8]) -> ATAResult<()> {
    assert_eq!(command.len(), 12);

    // SAFETY: `assert!` checked that slice has needed amount of bytes.
    let command16 = unsafe {
        [
            (*command.get_unchecked(1) as u16) << 8 | (*command.get_unchecked(0) as u16),
            (*command.get_unchecked(3) as u16) << 8 | (*command.get_unchecked(2) as u16),
            (*command.get_unchecked(5) as u16) << 8 | (*command.get_unchecked(4) as u16),
            (*command.get_unchecked(7) as u16) << 8 | (*command.get_unchecked(6) as u16),
            (*command.get_unchecked(9) as u16) << 8 | (*command.get_unchecked(8) as u16),
            (*command.get_unchecked(11) as u16) << 8 | (*command.get_unchecked(10) as u16),
        ]
    };

    send_scsi(drive, lba, &command16)
}

pub fn receive_size_of_transfer(drive: &ATAPhysicalDrive) -> ATAResult<u16> {
    ide_poll(drive.bus.io())?;

    let port = drive.pio_port();

    let high = unsafe { port.offset(ATA_REG_LBA2).read8() } as u16;
    let low = unsafe { port.offset(ATA_REG_LBA1).read8() } as u16;

    Ok((high << 8) | low)
}

pub fn read_result(drive: &ATAPhysicalDrive, buffer: &mut [u16]) {
    unsafe { drive.pio_port().offset(ATA_REG_DATA).read16_bulk(buffer) };
}

pub fn read_medium_capacity(drive: &ATAPhysicalDrive) -> ATAResult<(usize, usize)> {
    let command: [u16; 6] = [(ATAPI_CMD_READ_CAPACITY as u16), 0, 0, 0, 0, 0];

    send_scsi(drive, 8, &command)?;

    let transfer_size = receive_size_of_transfer(drive)?;

    let mut data = vec![0u16; (transfer_size / 2) as _];

    read_result(drive, &mut data);

    let max_lba = {
        let data = &data[0..2];

        (data[0] as u32) << 8 | (data[1] as u32)
    };

    let block_size = {
        let data = &data[2..4];

        (data[0] as u32) << 8 | (data[1] as u32)
    };

    Ok((max_lba as _, block_size as _))
}

pub fn read_sectors(drive: &ATAPhysicalDrive, lba: u32, buffer: &mut [u8]) -> ATAIOResult<()> {
    // SAFETY: For ATAPI devices, the block size is always sepcified, so unwrap will always succeed.
    let blksize = unsafe { drive.block_size().unwrap_unchecked() };

    assert!(buffer.len().is_multiple_of(blksize));

    let count = buffer.len() / blksize;

    let command: [u8; 12] = [
        ATAPI_CMD_READ,
        0,                            // Reserved or flags (usually zero)
        ((lba >> 0x18) & 0xFF) as u8, // LBA
        ((lba >> 0x10) & 0xFF) as u8,
        ((lba >> 0x08) & 0xFF) as u8,
        ((lba >> 0x00) & 0xFF) as u8,
        ((count >> 0x18) & 0xFF) as u8, // Sector count
        ((count >> 0x10) & 0xFF) as u8,
        ((count >> 0x08) & 0xFF) as u8,
        ((count >> 0x00) & 0xFF) as u8,
        0, // Reserved (usually zero)
        0, // Control (usually zero)
    ];

    send_scsi8(drive, blksize as _, &command).map_err(ATAIOError::ControllerError)?;

    ide_poll(drive.bus.io()).map_err(ATAIOError::ControllerError)?;

    let data_port = drive.pio_port().offset(ATA_REG_DATA);

    for i in 0..count {
        ide_poll(drive.bus.io()).map_err(ATAIOError::ControllerError)?;

        let ts = receive_size_of_transfer(drive).map_err(ATAIOError::ControllerError)?;

        let slice = &mut buffer[i * blksize..][..ts as usize];

        assert!(slice.len().is_multiple_of(2));

        let data_buf16 = unsafe {
            core::slice::from_raw_parts_mut(slice.as_mut_ptr().cast::<u16>(), slice.len() / 2)
        };

        unsafe { data_port.read16_bulk(data_buf16) };
    }

    Ok(())
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartStopOperation {
    Stop = 0b00,
    Start = 0b01,
    Eject = 0b10,
    Load = 0b11,
}

pub fn start_stop(drive: &ATAPhysicalDrive, op: StartStopOperation) -> ATAIOResult<()> {
    let mut command: [u16; 6] = [(ATAPI_CMD_START_STOP as u16), 0, 0, 0, 0, 0];

    // Byte 4:
    //   Bit 0: Start
    //   Bit 1: LoEj

    // LoEj      Start      Result
    //  0          0     Stop the Disc
    //  0          1     Start the Disc
    //  1          0     Eject Disc
    //  1          1     Close the Tray (Load the Disc)

    unsafe { command.as_mut_ptr().cast::<u8>().add(4).write(op as u8) };

    send_scsi(drive, 0, &command).map_err(ATAIOError::ControllerError)?;

    Ok(())
}
