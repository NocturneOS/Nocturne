use core::ffi::c_char;

use noct_fs::parser::PathParser;
use noct_fsman::entity::EntityType;
use noct_io::error::Error;
use noct_logger::qemu_log;

use crate::mem::usermem::{copy_user_string, verify_ptr_range_mut};

pub fn getcwd(buf: usize, size: usize, _: usize, _: usize, _: usize) -> Result<usize, Error> {
    let Some(ptr) = verify_ptr_range_mut::<c_char>(buf, size) else {
        qemu_log!("Error: {buf:x} with size {size} is not within program's address space!");

        return Err(Error::MemoryError);
    };

    let cwd = noct_sched::this_process().cwd();

    // Leave room for the string's NUL terminator.
    if size <= cwd.len() {
        return Err(Error::InvalidArgument);
    }

    unsafe {
        cwd.as_ptr().cast::<c_char>().copy_to(ptr, cwd.len());
        ptr.add(cwd.len()).write(0);
    }

    Ok(buf)
}

pub fn chdir(relpath: usize, _: usize, _: usize, _: usize, _: usize) -> Result<usize, Error> {
    let path = copy_user_string(relpath)?;

    let proc = noct_sched::this_process();
    let cwd = proc.cwd();

    let full_path = PathParser::resolve(&path, &cwd).ok_or(Error::InvalidPath)?;

    let (disk_id, fs_path) = full_path.split_once(':').ok_or(Error::InvalidPath)?;

    // If disk not found, error with NoDrive.
    if noct_fsman::mount::get_handle(disk_id).is_none() {
        return Err(Error::NoDrive);
    }

    // If we are not going to root...
    if fs_path != "/" {
        let info = noct_fs::info(&full_path)?;
        
        // And if the target path is not actually a directory, bail out.
        if info.entity_type != EntityType::Directory {
            return Err(Error::InvalidEntity);
        }
    }

    proc.chdir(&full_path);

    Ok(0)
}
