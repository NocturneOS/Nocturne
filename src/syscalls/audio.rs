use noct_io::error::Error;
use noct_logger::qemu_log;

use crate::mem::usermem;

pub fn open(id: usize, _: usize, _: usize, _: usize, _: usize) -> Result<usize, Error> {
    let dev = noct_audio::get_device(id).ok_or(Error::NotFound)?;

    dev.open();

    Ok(0)
}

pub fn close(id: usize, _: usize, _: usize, _: usize, _: usize) -> Result<usize, Error> {
    let dev = noct_audio::get_device(id).ok_or(Error::NotFound)?;

    dev.close();

    Ok(0)
}

pub fn manage(id: usize, command: usize, command_data: usize, len: usize, _: usize) -> Result<usize, Error> {
    let dev = noct_audio::get_device(id).ok_or(Error::NotFound)?;

    // That command is for the audio system itself, not for specific device.
    let is_global = command == usize::MAX;

    todo!()
}

pub fn read(id: usize, _: usize, _: usize, _: usize, _: usize) -> Result<usize, Error> {
    let dev = noct_audio::get_device(id).ok_or(Error::NotFound)?;

    Err(Error::Unimplemented)
}

pub fn write(id: usize, data_ptr: usize, len: usize, _: usize, _: usize) -> Result<usize, Error> {
    let dev = noct_audio::get_device(id).ok_or(Error::NotFound)?;

    qemu_log!("Data PTR: {data_ptr:08x?}; LEN: {len:?}");

    let data_ptr = usermem::verify_ptr_range::<u8>(data_ptr, len).ok_or(Error::MemoryError)?;
    
    let data = unsafe { core::slice::from_raw_parts(data_ptr, len) };

    dev.write(data);

    Ok(len)
}