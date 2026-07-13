use crate::qemu_log;
use noct_tty::tty_print;

pub fn write_tty(data: usize, len: usize, _: usize, _: usize, _: usize) -> Option<usize> {
    let data = data as *const u8;

    qemu_log!("Data: {data:?}; Length: {len}");

    let slice = unsafe { core::slice::from_raw_parts(data, len) };

    let Ok(string) = str::from_utf8(slice) else {
        return Some(0);
    };

    tty_print!("{string}");

    None
}
