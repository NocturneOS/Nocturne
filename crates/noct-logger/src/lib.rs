#![no_std]

extern crate alloc;

pub use noct_time;

use core::fmt::{self, Write};

// use noct_tools::interrupt_locker::InterruptLocker;

pub struct SerialWriter {
    pub port: u16,
}

pub fn __qemu_print(args: fmt::Arguments) {
    // let il = InterruptLocker::lock();

    let mut writer = SerialWriter { port: 0x3f8 };

    writer.write_fmt(args).unwrap();

    // drop(il);
}

impl fmt::Write for SerialWriter {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for i in s.bytes() {
            unsafe {
                x86::io::outb(self.port, i);
            }
        }

        Ok(())
    }
}

#[macro_export]
macro_rules! qemu_print {
    ($($arg:tt)*) => {
        $crate::__qemu_print(format_args!($($arg)*))
    };
}

#[macro_export]
macro_rules! qemu_println {
    () => {
        $crate::qemu_print!("\n")
    };
    ($($arg:tt)*) => {
        $crate::qemu_print!("{}\n", format_args!($($arg)*))
    };
}

#[macro_export]
macro_rules! qemu_log {
    ($($arg:tt)*) => {
        let factor = 1_000_000_000;
        let time = $crate::noct_time::systemclock::get_uptime_nanos();

        $crate::qemu_print!("<{:3}.{:09}> {}\n", time / factor, time % factor, format_args!($($arg)*))
    };
}
