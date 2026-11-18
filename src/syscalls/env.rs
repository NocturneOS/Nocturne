use alloc::string::ToString;
use noct_fs::parser::PathParser;
use noct_io::error::Error;
use noct_logger::qemu_log;
use core::ffi::{CStr, c_char};

use crate::mem::usermem::{verify_ptr, verify_ptr_range_mut};

pub fn getcwd(buf: usize, size: usize, _: usize, _: usize, _: usize) -> Result<usize, Error> {
    let Some(ptr) = verify_ptr_range_mut::<c_char>(buf, size) else {
        
        qemu_log!("Error: {buf:x} with size {size} is not within program's address space!");
        
        return Err(Error::MemoryError);
    };

    let proc = noct_sched::this_process();
    let cwd = proc.cwd();

    unsafe { cwd.as_ptr().cast::<c_char>().copy_to(ptr, cwd.len()) };

    Ok(buf)
}

pub fn chdir(relpath: usize, _: usize, _: usize, _: usize, _: usize) -> Result<usize, Error> {
    let path_ptr = verify_ptr::<u8>(relpath).ok_or(Error::MemoryError)?;

    let cstr = unsafe { CStr::from_ptr(path_ptr.cast::<c_char>()) };
    let append = &cstr.to_string_lossy();
    
    let proc = noct_sched::this_process();
    
    let is_absolute = PathParser::is_absolute(append);

    if is_absolute {
        proc.chdir(append);
    } else {
        let cwd = proc.cwd();

        let mut clear_path = PathParser::canonicalize(&cwd) + "/";

        clear_path += &PathParser::canonicalize(append);

        proc.chdir(&clear_path);
    }

    Ok(0)
}