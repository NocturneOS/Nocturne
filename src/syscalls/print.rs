use crate::qemu_log;
use noct_io::error::Error;
use noct_tty::tty_print;

pub fn write_tty(data: usize, len: usize, _: usize, _: usize, _: usize) -> Result<usize, Error> {
    let data = data as *const u8;

    qemu_log!("Data: {data:?}; Length: {len}");

    let slice = unsafe { core::slice::from_raw_parts(data, len) };

    let Ok(string) = str::from_utf8(slice) else {
        return Err(Error::MemoryError);
    };

    tty_print!("{string}");

    Ok(0)
}
