use noct_io::error::Error;
use noct_logger::qemu_log;

pub fn debug(data_ptr: usize, len: usize, _arg3: usize, _arg4: usize, _arg5: usize) -> Result<usize, Error> {
    qemu_log!("Syscall debug: {data_ptr:x} {len} ({data_ptr} {len} {_arg3} {_arg4} {_arg5})");

    let u8ptr = data_ptr as *const u8;
    let data = unsafe { core::slice::from_raw_parts(u8ptr, len) };

    qemu_log!("Debug! {data:?} {:?}", str::from_utf8(data).unwrap());

    Ok(0)
}

pub fn reg_debug(arg1: usize, arg2: usize, arg3: usize, arg4: usize, arg5: usize) -> Result<usize, Error> {
    qemu_log!("Syscall debug: ARG1 = {arg1:x}; ARG2 = {arg2:x}; ARG3 = {arg3:x}; ARG4 = {arg4:x}; ARG5 = {arg5:x};");
    
    Ok(0)
}