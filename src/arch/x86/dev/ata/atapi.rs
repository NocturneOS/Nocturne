use alloc::vec;
use noct_diskman::drive::Drive;
use noct_logger::qemu_log;

use crate::arch::x86::dev::ata::{
    ATABus, ATADrive,
    commands::{ATA_CMD_PACKET, ATAPI_CMD_READ, ATAPI_CMD_READ_CAPACITY},
    drive::ATAPhysicalDrive,
    error::{ATAError, ATAIOError, ATAIOResult, ATAResult},
    ide_400ns_delay, ide_poll, ide_select_drive,
    regs::{ATA_REG_COMMAND, ATA_REG_DATA, ATA_REG_ERROR, ATA_REG_LBA1, ATA_REG_LBA2},
};

pub fn send_scsi(drive: &ATAPhysicalDrive, lba: u16, command: &[u16]) -> ATAResult<()> {
    assert!(command.len() <= 16);

    ide_select_drive(drive.bus, drive.drive);

    let port = drive.pio_port();

    port.offset(ATA_REG_ERROR).write8(0);
    port.offset(ATA_REG_LBA1).write8((lba & 0xff) as _);
    port.offset(ATA_REG_LBA2).write8(((lba >> 8) & 0xff) as _);
    port.offset(ATA_REG_COMMAND).write8(ATA_CMD_PACKET);

    ide_400ns_delay(drive.bus.io());

    ide_poll(drive.bus.io())?;

    port.offset(ATA_REG_DATA).write16_bulk(command);

    Ok(())
}

pub fn receive_size_of_transfer(drive: &ATAPhysicalDrive) -> ATAResult<u16> {
    ide_poll(drive.bus.io())?;

    let port = drive.pio_port();

    let high = port.offset(ATA_REG_LBA2).read8() as u16;
    let low = port.offset(ATA_REG_LBA1).read8() as u16;

    Ok((high << 8) | low)
}

pub fn read_result(drive: &ATAPhysicalDrive, buffer: &mut [u16]) {
    let port = drive.pio_port();

    port.offset(ATA_REG_DATA).read16_bulk(buffer);
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
    let blksize = drive.block_size().unwrap();

    assert!(buffer.len().is_multiple_of(blksize));

    let count = buffer.len() / blksize;

    let command: [u8; 12] = [
        ATAPI_CMD_READ,
        0, // ?
        ((lba >> 0x18) & 0xFF) as u8, // LBA
        ((lba >> 0x10) & 0xFF) as u8,
        ((lba >> 0x08) & 0xFF) as u8,
        ((lba >> 0x00) & 0xFF) as u8,
        ((count >> 0x18) & 0xFF) as u8, // Sector count
        ((count >> 0x10) & 0xFF) as u8,
        ((count >> 0x08) & 0xFF) as u8,
        ((count >> 0x00) & 0xFF) as u8,
        0, // ?
        0, // ?
    ];

    let command16 = unsafe { core::slice::from_raw_parts(command.as_ptr().cast::<u16>(), 6) };

    send_scsi(drive, blksize as _, &command16).map_err(ATAIOError::ControllerError)?;

    ide_poll(drive.bus.io()).map_err(ATAIOError::ControllerError)?;

    // let transf_size = receive_size_of_transfer(drive).map_err(ATAIOError::ControllerError)?;

    // qemu_log!("Transfer size: {transf_size}");

    let data_port = drive.pio_port().offset(ATA_REG_DATA);

    for i in 0..count {
        ide_poll(drive.bus.io()).map_err(ATAIOError::ControllerError)?;
        
        let ts = receive_size_of_transfer(drive).map_err(ATAIOError::ControllerError)?;

        let slice = &mut buffer[i * blksize..][..ts as usize];

        assert!(slice.len().is_multiple_of(2));

        let data_buf16 = unsafe {
            core::slice::from_raw_parts_mut(slice.as_mut_ptr().cast::<u16>(), slice.len() / 2)
        };

        data_port.read16_bulk(data_buf16);
    }

    Ok(())
}
