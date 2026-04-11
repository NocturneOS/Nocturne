use core::arch::asm;

use noct_logger::qemu_log;
use x86::io::{inb, outb};

use super::{PS2_DATA_PORT, PS2_STATE_REG};

/// Reads configuration byte register from PCI CONTROLLER
///
/// # Safety
/// It uses IO ports
pub extern "C" fn read_configuration_byte() -> u8 {
    in_wait_until_empty();
    unsafe { outb(PS2_STATE_REG, 0x20) };

    read()
}

/// # Safety
/// It uses IO ports
pub unsafe extern "C" fn write_configuration_byte(byte: u8) {
    in_wait_until_empty();
    unsafe { outb(PS2_STATE_REG, 0x60) };

    unsafe { write(byte) };
}

/// # Safety
/// It uses IO ports
fn in_wait_until_empty() {
    while (unsafe { inb(PS2_STATE_REG) } & (1 << 1)) != 0 {
        unsafe {
            core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
            asm!("nop");
        }
    }
}

/// # Safety
/// It uses IO ports
fn out_wait_until_full() {
    while (unsafe { inb(PS2_STATE_REG) } & 1) == 0 {
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}

/// Reads byte from PCI Controller
/// # Safety
/// It uses IO ports
pub extern "C" fn read() -> u8 {
    out_wait_until_full();

    unsafe { inb(PS2_DATA_PORT) }
}

/// # Safety
/// It uses IO ports
pub unsafe extern "C" fn write(byte: u8) {
    in_wait_until_empty();
    unsafe { outb(PS2_DATA_PORT, byte) };
}

pub fn disable_first_device() {
    unsafe {
        in_wait_until_empty();
        outb(PS2_STATE_REG, 0xAD); // 1
    };
}

pub fn disable_second_device() {
    in_wait_until_empty();
    unsafe { outb(PS2_STATE_REG, 0xA7) }; // 2
}

pub fn enable_first_device() {
    in_wait_until_empty();
    unsafe { outb(PS2_STATE_REG, 0xAE) }; // 1
}

pub fn enable_second_device() {
    in_wait_until_empty();
    unsafe { outb(PS2_STATE_REG, 0xA8) }; // 2
}

pub fn flush() {
    unsafe {
        while (inb(PS2_STATE_REG) & 1) != 0 {
            inb(PS2_DATA_PORT);
        }
    }
}

fn test() -> Option<()> {
    unsafe {
        in_wait_until_empty();

        outb(PS2_STATE_REG, 0xAA);
    } // Test command

    out_wait_until_full();

    let reply: u8 = unsafe { inb(PS2_DATA_PORT) };

    if reply == 0x55 { Some(()) } else { None }
}

pub fn init() -> (bool, bool) {
    let mut first_device_ok = false;
    let mut second_device_ok = false;

    disable_first_device();
    disable_second_device();

    flush();

    in_wait_until_empty();

    let conf: u8 = read_configuration_byte();
    unsafe { write_configuration_byte(conf & !(0b0100_0011)) };

    // TEST CONTROLLER

    let test_ok = test();

    if test_ok.is_none() {
        qemu_log!("PS/2 TEST ERROR!");
        return (false, false);
    }

    qemu_log!("PS/2 test ok!");

    // Test first port

    in_wait_until_empty();
    unsafe { outb(PS2_STATE_REG, 0xAB) };

    out_wait_until_full();
    let mut result: u8 = unsafe { inb(PS2_DATA_PORT) };

    if result == 0x00 {
        qemu_log!("Passed test for channel 1!");
        first_device_ok = true;
    } else {
        qemu_log!("Channel 1: Test failed! Result: {:x}", result);
    }

    // Test second port

    unsafe {
        in_wait_until_empty();
        outb(PS2_STATE_REG, 0xA9);

        out_wait_until_full()
    };

    result = unsafe { inb(PS2_DATA_PORT) };

    if result == 0x00 {
        qemu_log!("Passed test for channel 2!");
        second_device_ok = true;
    } else {
        qemu_log!("Channel 2: Test failed! Result: {:x}", result);
    }

    enable_first_device();
    enable_second_device();

    (first_device_ok, second_device_ok)
}
