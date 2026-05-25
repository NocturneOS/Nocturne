use noct_logger::qemu_log;

pub fn debug(data_ptr: usize, len: usize, _arg3: usize, _arg4: usize, _arg5: usize) -> Option<usize> {
    let u8ptr = data_ptr as *const u8;
    let data = unsafe { core::slice::from_raw_parts(u8ptr, len) };

    qemu_log!("Debug! {data:?} {:?}", str::from_utf8(data).unwrap());

    None
}