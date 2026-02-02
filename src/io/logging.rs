use core::fmt::{self, Write};

use lazy_static::lazy_static;

use crate::{arch, tools::pseudosync::PseudoSync};

lazy_static! {
    // pub static ref QEMU: Mutex<SerialWriter> = Mutex::new(SerialWriter { port: 0x3f8 });
    pub static ref QEMU: PseudoSync<SerialWriter> = PseudoSync::new(SerialWriter { port: 0x3f8 });
}

pub struct SerialWriter {
    pub port: u16,
}

pub fn __qemu_print(args: fmt::Arguments) {
    let is_ena = arch::are_interrupts_enabled();

    arch::disable_interrupts();

    unsafe { QEMU.get_mut().write_fmt(args).unwrap() };

    if is_ena {
        arch::enable_interrupts();
    }
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
        $crate::io::logging::__qemu_print(format_args!($($arg)*))
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
        let time = $crate::time::get_uptime_nanos();

        $crate::qemu_print!("<{:3}.{:09}> {}\n", time / factor, time % factor, format_args!($($arg)*))
    };
}
