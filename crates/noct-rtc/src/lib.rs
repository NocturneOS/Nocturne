#![no_std]

use core::sync::atomic::{AtomicU64, Ordering};

use noct_cpu::CPURegisters;
use noct_interrupts::handler::register_interrupt_handler;
use noct_ioport::IOPort;
use noct_time::repr::DateTime;
use noct_tools::without_interrupts::without_interrupts;

const CMOS_ADDRESS_PORT: IOPort = IOPort::new(0x70);
const CMOS_DATA_PORT: IOPort = IOPort::new(0x71);

const RTC_SECONDS: u8 = 0x00;
const RTC_MINUTES: u8 = 0x02;
const RTC_HOURS: u8 = 0x04;
const RTC_DAY_OF_MONTH: u8 = 0x07;
const RTC_MONTH: u8 = 0x08;
const RTC_YEAR: u8 = 0x09;
const RTC_STAT_A: u8 = 0x0A;
const RTC_STAT_B: u8 = 0x0B;
const RTC_STAT_C: u8 = 0x0C;

static TIMER_AT_SYNC: AtomicU64 = AtomicU64::new(0);

pub fn init() {
    register_interrupt_handler(0x20 + 8, interrupt_handler);

    // 32768 >> (rate - 1) = 32768 >> 14 = 2 Hz
    set_interrupt_rate(15);

    without_interrupts(|| {
        let old = read_reg(RTC_STAT_B);

        // Enable interrupts.
        write_reg(RTC_STAT_B, old | 0x10);
    });
}

fn set_interrupt_rate(mut rate: u8) {
    rate &= 0x0F;

    without_interrupts(|| {
        let old = read_reg(RTC_STAT_A);

        write_reg(RTC_STAT_A, (old & 0xF0) | rate);
    });
}

fn update_in_progress() -> bool {
    unsafe {
        CMOS_ADDRESS_PORT.write8(0x0A);

        (CMOS_DATA_PORT.read8() & 0x80) != 0
    }
}

fn read_reg(register: u8) -> u8 {
    unsafe {
        CMOS_ADDRESS_PORT.write8(register | (1 << 7));

        CMOS_DATA_PORT.read8()
    }
}

fn write_reg(register: u8, value: u8) {
    unsafe {
        CMOS_ADDRESS_PORT.write8(register | (1 << 7));

        CMOS_DATA_PORT.write8(value);
    }
}

fn wait() {
    while update_in_progress() {
        noct_cpu::halt::halt();
    }
}

pub fn read() -> DateTime {
    wait();

    let mut sec = read_reg(RTC_SECONDS);
    let mut minute = read_reg(RTC_MINUTES);
    let mut hour = read_reg(RTC_HOURS);
    let mut day = read_reg(RTC_DAY_OF_MONTH);
    let mut month = read_reg(RTC_MONTH);
    let mut year = read_reg(RTC_YEAR);

    let register_b = read_reg(RTC_STAT_B);

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

    let millis: u128 =
        noct_time::systemclock::get_uptime_millis() - TIMER_AT_SYNC.load(Ordering::Relaxed) as u128;

    DateTime::new(
        year,
        month,
        day,
        hour,
        minute,
        sec,
        (millis.clamp(0, 999)) as _,
    )
    .unwrap()
}

extern "C" fn interrupt_handler(_regs: &mut CPURegisters) {
    TIMER_AT_SYNC.store(
        noct_time::systemclock::get_uptime_millis() as _,
        Ordering::Release,
    );

    // RTC EOI
    let _ = read_reg(RTC_STAT_C);
}
