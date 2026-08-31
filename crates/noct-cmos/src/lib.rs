#![no_std]

use noct_ioport::IOPort;
use noct_time::repr::DateTime;

const CMOS_ADDRESS_PORT: IOPort = IOPort::new(0x70);
const CMOS_DATA_PORT: IOPort = IOPort::new(0x71);

fn update_in_progress() -> bool {
    unsafe {
        CMOS_ADDRESS_PORT.write8(0x0A);

        (CMOS_DATA_PORT.read8() & 0x80) != 0
    }
}

fn read_reg(register: u8) -> u8 {
    unsafe {
        CMOS_ADDRESS_PORT.write8(register);

        CMOS_DATA_PORT.read8()
    }
}

fn wait() {
    while update_in_progress() {
        noct_cpu::halt::halt();
    }
}

pub fn read() -> DateTime {
    wait();

    let mut sec = read_reg(0);
    let mut minute = read_reg(2);
    let mut hour = read_reg(4);
    let mut day = read_reg(7);
    let mut month = read_reg(8);
    let mut year = read_reg(9);

    let register_b = read_reg(0x0b);

    let is_bcd = (register_b & 0x04) == 0;

    if is_bcd {
        fn quick_conv(bcd: u8) -> u8 {
            (bcd & 0xf) + ((bcd >> 4) * 10)
        }

        sec = quick_conv(sec);
        minute = quick_conv(minute);
        hour = ((hour & 0xf) + (((hour & 0x70) >> 4) * 10)) | (hour & 0x80);
        day = quick_conv(day);
        month = quick_conv(month);
        year = quick_conv(year);
    }

    let clock_format_12 = (register_b & 0x02) == 0;
    let am_pm_bit = (hour & 0x80) == 0;

    if clock_format_12 && am_pm_bit {
        hour = ((hour & 0x7f) + 12) % 24;
    }

    let mut year = year as u16;

    // TODO: Use ACPI's Century Register to determine the century.
    year += 2000;

    DateTime::new(year, month, day, hour, minute, sec).unwrap()
}