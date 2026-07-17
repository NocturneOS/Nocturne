use core::{ffi::CStr, fmt::Write as FmtWrite};

use alloc::borrow::ToOwned;
use noct_descriptor::ResourceDescriptor;
use noct_fsman::handles::file::FileOpenMode;
use noct_io::{Read, Seek, SeekOffset, Write};
use noct_logger::qemu_log;

use bitflags::bitflags;

bitflags! {
    #[derive(Debug, Clone, Copy)]
    pub struct OpenFlags: u32 {
        // These flags should copy FileOpenMode from noct_fsman
        const Read = 1 << 0;
        const Write = 1 << 1;
        const Truncate = 1 << 2;

        // Additional flags go here.

        const Directory = 1 << 3;
    }
}

pub fn open(path: usize, mode: usize, _: usize, _: usize, _: usize) -> Option<usize> {
    // TODO: Sanitize that.
    // TODO: Set error on utf8 encoding failure
    let path = unsafe { CStr::from_ptr(path as *const core::ffi::c_char) }
        .to_str()
        .ok()?
        .to_owned();

    let flags = OpenFlags::from_bits_truncate(mode as _);

    let handle = if flags.contains(OpenFlags::Directory) {
        let dir = match noct_fs::open_directory(&path) {
            Ok(dh) => dh,
            Err(e) => {
                noct_sched::set_error(e as _);

                return None;
            }
        };

        ResourceDescriptor::DirectoryHandle(dir)
    } else {
        let fh = match noct_fs::open_file(&path, FileOpenMode::from_bits_truncate(mode as _)) {
            Ok(fh) => fh,
            Err(e) => {
                noct_sched::set_error(e as _);

                return None;
            }
        };

        ResourceDescriptor::FileStream(fh)
    };

    let process = &noct_sched::this_thread().process;

    let mut reslock = process.resources.lock();

    reslock.make(handle);

    None
}

pub fn close(fd: usize, _: usize, _: usize, _: usize, _: usize) -> Option<usize> {
    let process = &noct_sched::this_thread().process;

    let mut reslock = process.resources.lock();

    reslock.close(fd);

    None
}

pub fn read(fd: usize, data: usize, len: usize, _: usize, _: usize) -> Option<usize> {
    let ptr = data as *mut u8;
    let slice = unsafe { core::slice::from_raw_parts_mut(ptr, len) };

    // Test-fill that. If this call causes an exception (due to Page Fault / GPF) it will kill whole process.
    slice.fill(0);

    let process = &noct_sched::this_thread().process;

    let mut lock = process.resources.lock();

    let fd_val = lock.find_mut(fd)?;

    qemu_log!("read: fd {fd} -> {:?}", fd_val.res);

    match &mut fd_val.res {
        ResourceDescriptor::Null => return Some(0),
        ResourceDescriptor::TerminalInput => {
            todo!("Implement input from terminal!");
        }
        ResourceDescriptor::TerminalOutput => {
            noct_sched::set_error(noct_io::error::Error::InvalidHandle as _)
        }
        ResourceDescriptor::DirectoryHandle(_) => {
            noct_sched::set_error(noct_io::error::Error::InvalidHandle as _)
        }
        ResourceDescriptor::FileStream(file_handle) => {
            let value = file_handle.read(slice);

            match value {
                Err(e) => noct_sched::set_error(e as _),
                Ok(read_bytes) => return Some(read_bytes as _),
            }
        }
    }

    None
}

pub fn write(fd: usize, data: usize, len: usize, _: usize, _: usize) -> Option<usize> {
    let ptr = data as *const u8;
    let slice = unsafe { core::slice::from_raw_parts(ptr, len) };

    let process = &noct_sched::this_thread().process;

    let mut lock = process.resources.lock();

    let fd_val = lock.find_mut(fd)?;

    qemu_log!("write: fd {fd} -> {:?}", fd_val.res);

    match &mut fd_val.res {
        ResourceDescriptor::Null => return Some(0),
        ResourceDescriptor::TerminalInput => {
            noct_sched::set_error(noct_io::error::Error::InvalidHandle as _)
        }
        ResourceDescriptor::TerminalOutput => {
            let result = noct_tty::WRITER
                .lock()
                .write_str(unsafe { str::from_utf8_unchecked(slice) });

            if let Err(e) = result {
                noct_sched::set_error(noct_io::error::Error::IoError as _)
            }
        }
        ResourceDescriptor::FileStream(file_handle) => {
            let value = file_handle.write(slice);

            match value {
                Err(e) => noct_sched::set_error(e as _),
                Ok(written_bytes) => return Some(written_bytes as _),
            }
        }
        ResourceDescriptor::DirectoryHandle(_) => {
            noct_sched::set_error(noct_io::error::Error::InvalidHandle as _)
        }
    }

    None
}

pub fn seek(fd: usize, offset: usize, whence: usize, _: usize, _: usize) -> Option<usize> {
    let process = &noct_sched::this_thread().process;

    let mut lock = process.resources.lock();

    let fd_val = lock.find_mut(fd)?;

    match &mut fd_val.res {
        ResourceDescriptor::Null => return Some(0),
        ResourceDescriptor::TerminalInput | ResourceDescriptor::TerminalOutput | ResourceDescriptor::DirectoryHandle(_) => {
            noct_sched::set_error(noct_io::error::Error::InvalidHandle as _)
        }
        ResourceDescriptor::FileStream(file_handle) => {
            let so = match whence {
                0 => SeekOffset::Beginning(offset as _),
                1 => SeekOffset::Current(offset as _),
                2 => SeekOffset::End(offset as _),
                _ => {
                    noct_sched::set_error(noct_io::error::Error::InvalidSeek as _);

                    return None;
                }
            };

            let value = file_handle.seek(so);

            match value {
                Err(e) => noct_sched::set_error(e as _),
                Ok(position) => return Some(position as _),
            }
        }
    }

    None
}

pub fn tell(fd: usize, _: usize, _: usize, _: usize, _: usize) -> Option<usize> {
    let process = &noct_sched::this_thread().process;

    let mut lock = process.resources.lock();

    let fd_val = lock.find_mut(fd)?;

    match &mut fd_val.res {
        ResourceDescriptor::Null => return Some(0),
        ResourceDescriptor::TerminalInput | ResourceDescriptor::TerminalOutput | ResourceDescriptor::DirectoryHandle(_) => {
            noct_sched::set_error(noct_io::error::Error::InvalidHandle as _)
        }
        ResourceDescriptor::FileStream(file_handle) => {
            let value = file_handle.seek(SeekOffset::Current(0));

            match value {
                Err(e) => noct_sched::set_error(e as _),
                Ok(position) => return Some(position as _),
            }
        }
    }

    None
}
