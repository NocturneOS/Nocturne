#![no_std]

extern crate alloc;

pub mod input;
pub mod console;
pub mod renderer;

use core::fmt;
use core::fmt::Write;
use lazy_static::lazy_static;
use spin::Mutex;

use crate::console::Console;
use crate::renderer::RenderedConsole;

#[macro_export]
macro_rules! tty_print {
    ($($arg:tt)*) => ($crate::_print_tty(format_args!($($arg)*)));
}

#[macro_export]
macro_rules! tty_println {
    () => ($crate::tty_print!("\n"));
    ($($arg:tt)*) => ($crate::tty_print!("{}\n", format_args!($($arg)*)));
}

#[doc(hidden)]
pub fn _print_tty(args: fmt::Arguments) {
    WRITER.lock().write_fmt(args).unwrap();
}

lazy_static! {
    pub static ref WRITER: Mutex<Writer> = Mutex::new(Writer::default());
}

#[derive(Default)]
pub struct Writer {
    console: Option<RenderedConsole>
}

impl fmt::Write for Writer {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        assert!(self.console.is_some(), "Attempted usage of uninitialized console!");

        self.console.as_mut().unwrap().print_str(s);

        Ok(())
    }
}

impl Writer {
    pub fn flush(&mut self) {
        assert!(self.console.is_some(), "Attempted usage of uninitialized console!");

        self.console.as_mut().unwrap().render();
    }
}

pub fn init(console_rows: usize, console_columns: usize) {
    *WRITER.lock() = Writer { console: Some(RenderedConsole::new(Console::new(console_rows, console_columns))) };

    input::init();
}