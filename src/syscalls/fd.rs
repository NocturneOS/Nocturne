use core::{ffi::CStr, fmt::Write as FmtWrite, time::Duration};

use alloc::borrow::ToOwned;
use noct_descriptor::ResourceDescriptor;
use noct_fsman::handles::file::FileOpenMode;
use noct_io::{Read, Seek, SeekOffset, Write, error::Error};
use noct_logger::qemu_log;

use bitflags::bitflags;

use crate::mem::usermem::{verify_ptr, verify_ptr_range, verify_ptr_range_mut};

bitflags! {
    #[derive(Debug, Clone, Copy)]
    pub struct OpenFlags: u32 {
        // First flags are copied from noct_fsman::FileOpenFlags
        const Directory = 1 << 5;
    }
}

pub fn open(path: usize, mode: usize, _: usize, _: usize, _: usize) -> Result<usize, Error> {
    // TODO: Sanitize that.
    // TODO: Set error on utf8 encoding failure
    let path = verify_ptr(path).ok_or(Error::MemoryError)?;

    let path = unsafe { CStr::from_ptr(path) }
        .to_str()
        .map(|path| path.to_owned());

    let mut path = match path {
        Ok(path) => path,
        Err(e) => {
            qemu_log!("open: Error while decoding UTF-8 path: {e:?}");

            return Err(Error::InvalidPath);
        }
    };

    let process = &noct_sched::this_thread().process;

    // If path is relative, add the CWD to make it absolute.
    if !path.contains(":/") {
        path.insert_str(0, &process.cwd());
    }

    qemu_log!("Opening path: {path:?}");

    let flags = OpenFlags::from_bits_truncate(mode as _);

    let handle = {
        if flags.contains(OpenFlags::Directory) {
            let dh = noct_fs::open_directory(&path)?;

            ResourceDescriptor::DirectoryHandle(dh)
        } else {
            let fh = noct_fs::open_file(&path, FileOpenMode::from_bits_truncate(mode as _))?;

            ResourceDescriptor::FileStream(fh)
        }
    };

    let mut reslock = process.resources.lock();

    let descr = reslock.make(handle);

    Ok(descr.id())
}

pub fn close(fd: usize, _: usize, _: usize, _: usize, _: usize) -> Result<usize, Error> {
    let process = &noct_sched::this_thread().process;

    {
        let mut reslock = process.resources.lock();

        reslock.close(fd);
    }

    // An event queue descriptor must also disappear from the dispatcher's listener list.
    noct_input_dispatcher::unregister(process.id, fd);

    Ok(0)
}

pub fn read(fd: usize, data: usize, len: usize, _: usize, _: usize) -> Result<usize, Error> {
    if len == 0 {
        return Ok(0);
    }

    let ptr = verify_ptr_range_mut::<u8>(data, len).ok_or(Error::MemoryError)?;
    let slice = unsafe { core::slice::from_raw_parts_mut(ptr, len) };

    let process = &noct_sched::this_thread().process;

    enum ReadAction {
        TerminalInput,
        Event(Option<noct_input::event::InputEvent>),
    }

    loop {
        let action = {
            let mut lock = process.resources.lock();

            let fd_val = lock.find_mut(fd).ok_or(Error::InvalidHandle)?;

            match &mut fd_val.res {
                ResourceDescriptor::Null => return Ok(0),
                ResourceDescriptor::TerminalInput => ReadAction::TerminalInput,
                ResourceDescriptor::EventQueue(queue) => {
                    if len < noct_input::event::EVENT_WIRE_SIZE {
                        return Err(Error::InvalidArgument);
                    }

                    ReadAction::Event(queue.get_raw())
                }
                ResourceDescriptor::FileStream(file_handle) => {
                    let read_bytes = file_handle.read(slice)?;

                    return Ok(read_bytes as usize);
                }
                _ => return Err(Error::InvalidHandle),
            }
        };

        match action {
            ReadAction::TerminalInput => {
                if let Some(ch) = noct_tty::input::try_read_char() {
                    slice[0] = ch;

                    noct_tty::tty_print!("{}", ch as char);
                    noct_tty::WRITER.lock().flush();

                    return Ok(1);
                }
            }
            ReadAction::Event(Some(event)) => {
                let written = event.serialize_into(slice).ok_or(Error::MemoryError)?;

                return Ok(written);
            }
            ReadAction::Event(None) => {}
        }

        // No data yet. A real wait queue can replace this polling loop later;
        // It's like in `waitpid` now.
        noct_sched::sleep(Duration::from_millis(1));
    }
}

pub fn write(fd: usize, data: usize, len: usize, _: usize, _: usize) -> Result<usize, Error> {
    if len == 0 {
        return Ok(0);
    }

    let ptr = verify_ptr_range::<u8>(data, len).ok_or(Error::MemoryError)?;
    let slice = unsafe { core::slice::from_raw_parts(ptr, len) };

    let process = &noct_sched::this_thread().process;

    let mut lock = process.resources.lock();

    // XXX: Or Error::NotFound?
    let fd_val = lock.find_mut(fd).ok_or(Error::InvalidHandle)?;

    // qemu_log!("write: fd {fd} -> {:?}", fd_val.res);

    match &mut fd_val.res {
        ResourceDescriptor::Null => return Ok(0),
        ResourceDescriptor::TerminalOutput => {
            let text = core::str::from_utf8(slice).map_err(|_| Error::InvalidArgument)?;

            noct_tty::WRITER
                .lock()
                .write_str(text)
                .map_err(|_| Error::Unknown)?;

            Ok(len)
        }
        ResourceDescriptor::FileStream(file_handle) => {
            let written_bytes = file_handle.write(slice)?;

            Ok(written_bytes as usize)
        }
        ResourceDescriptor::VideoLock(v) => {
            v.write(slice);

            Ok(slice.len())
        }
        _ => Err(noct_io::error::Error::InvalidHandle),
    }
}

pub fn seek(fd: usize, offset: usize, whence: usize, _: usize, _: usize) -> Result<usize, Error> {
    let process = &noct_sched::this_thread().process;

    let mut lock = process.resources.lock();

    let fd_val = lock.find_mut(fd).ok_or(Error::InvalidHandle)?;

    match &mut fd_val.res {
        ResourceDescriptor::Null => Ok(0),
        ResourceDescriptor::FileStream(file_handle) => {
            let so = match whence {
                0 => SeekOffset::Beginning(offset as _),
                1 => SeekOffset::Current(offset as _),
                2 => SeekOffset::End(offset as _),
                _ => {
                    return Err(noct_io::error::Error::InvalidSeek as _);
                }
            };

            let position = file_handle.seek(so)?;

            Ok(position as _)
        }
        ResourceDescriptor::VideoLock(v) => {
            match whence {
                0 => v.seek(offset as _),
                1 => v.seek(v.offset() + offset),
                2 => v.seek(v.buffer_len() - offset),
                _ => {
                    return Err(Error::InvalidSeek);
                }
            }

            Ok(v.offset())
        }
        _ => Err(Error::InvalidHandle),
    }
}

pub fn tell(fd: usize, _: usize, _: usize, _: usize, _: usize) -> Result<usize, Error> {
    let process = &noct_sched::this_thread().process;

    let mut lock = process.resources.lock();

    let fd_val = lock.find_mut(fd).ok_or(Error::InvalidHandle)?;

    match &mut fd_val.res {
        ResourceDescriptor::Null => Ok(0),
        ResourceDescriptor::FileStream(file_handle) => {
            let value = file_handle.seek(SeekOffset::Current(0));

            match value {
                Err(e) => Err(e),
                Ok(position) => Ok(position as _),
            }
        }
        ResourceDescriptor::VideoLock(v) => Ok(v.offset()),
        _ => Err(Error::InvalidHandle),
    }
}

pub fn flush(fd: usize, _: usize, _: usize, _: usize, _: usize) -> Result<usize, Error> {
    let process = &noct_sched::this_thread().process;

    let mut lock = process.resources.lock();

    let fd_val = lock.find_mut(fd).ok_or(Error::InvalidHandle)?;

    match &mut fd_val.res {
        ResourceDescriptor::Null => Ok(0),
        ResourceDescriptor::TerminalOutput => {
            noct_tty::WRITER.try_lock().ok_or(Error::Busy)?.flush();

            Ok(0)
        }
        ResourceDescriptor::FileStream(file_handle) => {
            file_handle.flush()?;

            Ok(0)
        }
        _ => Err(Error::InvalidHandle as _),
    }
}
