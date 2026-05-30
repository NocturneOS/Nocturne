use noct_logger::qemu_log;

pub fn debug(data_ptr: usize, len: usize, _arg3: usize, _arg4: usize, _arg5: usize) -> Option<usize> {
    qemu_log!("Syscall debug: {data_ptr:x} {len} ({data_ptr} {len} {_arg3} {_arg4} {_arg5})");

    let u8ptr = data_ptr as *const u8;
    let data = unsafe { core::slice::from_raw_parts(u8ptr, len) };

    qemu_log!("Debug! {data:?} {:?}", str::from_utf8(data).unwrap());

    None
}

pub fn reg_debug(arg1: usize, arg2: usize, arg3: usize, arg4: usize, arg5: usize) -> Option<usize> {
    qemu_log!("Syscall debug: EBX = {arg1:x}; ECX = {arg2:x}; EDX = {arg3:x}; ESI = {arg4:x}; EDI = {arg5:x};");
    
    None
}