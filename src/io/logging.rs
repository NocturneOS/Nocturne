use core::fmt::{self, Write};

use lazy_static::lazy_static;
use spin::Mutex;

lazy_static! {
    pub static ref QEMU: Mutex<SerialWriter> = Mutex::new(SerialWriter { port: 0x3f8 });
}

pub struct SerialWriter {
    port: u16,
}

pub fn __qemu_print(args: fmt::Arguments) {
    QEMU.lock().write_fmt(args).unwrap();
}

impl fmt::Write for SerialWriter {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for i in s.bytes() {
            unsafe {
                x86::io::outb(self.port, i as u8);
            }
        }

        Ok(())
    }
}

#[macro_export]
macro_rules! qemu_print {
    ($($arg:tt)*) => {
        crate::io::logging::__qemu_print(format_args!($($arg)*))
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