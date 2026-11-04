use core::{ffi::CStr, fmt::Write as FmtWrite};

use alloc::borrow::ToOwned;
use noct_descriptor::ResourceDescriptor;
use noct_fsman::handles::file::FileOpenMode;
use noct_io::{Read, Seek, SeekOffset, Write, error::Error};
use noct_logger::qemu_log;

use bitflags::bitflags;
use noct_sched::thread::ThreadWaitReason;

use crate::mem::usermem::verify_ptr;

bitflags! {
    #[derive(Debug, Clone, Copy)]
    pub struct OpenFlags: u32 {
        // First flags are copied from noct_fsman::FileOpenFlags
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
        let fh = match noct_fs::open_file(&path, FileOpenMode::from_bits_truncate(mode as _)) {
            Ok(fh) => fh,
            Err(e) => {
                return Err(Error::NotFound);
            }
        };

        ResourceDescriptor::FileStream(fh)
    };

    let mut reslock = process.resources.lock();

    let descr = reslock.make(handle);

    Ok(descr.id())
}

pub fn close(fd: usize, _: usize, _: usize, _: usize, _: usize) -> Result<usize, Error> {
    let process = &noct_sched::this_thread().process;

    let mut reslock = process.resources.lock();

    reslock.close(fd);

    Ok(0)
}

pub fn read(fd: usize, data: usize, len: usize, _: usize, _: usize) -> Result<usize, Error> {
    // FIXME: VERIFY THE POINTER IS WITHIN USERSPACE AREA!

    let ptr = data as *mut u8;
    let slice = unsafe { core::slice::from_raw_parts_mut(ptr, len) };

    // Test-fill that. If this call causes an exception (due to Page Fault / GPF) it will kill whole process.
    slice.fill(0);

    let process = &noct_sched::this_thread().process;

    let mut lock = process.resources.lock();

    let fd_val = lock.find_mut(fd).ok_or(Error::InvalidHandle)?;

    // qemu_log!("read: fd {fd} -> {:?}", fd_val.res);

    let mut input_needs_waiting = false;

    match &mut fd_val.res {
        ResourceDescriptor::Null => return Ok(0),
        ResourceDescriptor::TerminalInput => {
            let ifd = noct_tty::input::input_fd();

            // Kernel TTY is always in kernel process.
            let kproc = noct_sched::this().kernel_process().clone();

            let mut kres = kproc.resources.lock();

            let evq = kres
                .find_mut(ifd)
                .ok_or(Error::InvalidHandle)?
                .res
                .as_event_queue_mut()
                .expect("Input FD is not an EventQueue!");

            match noct_tty::input::get_char(evq) {
                Some(0) | None => {
                    input_needs_waiting = true;
                }
                Some(ch) => {
                    slice[0] = ch;

                    return Ok(1);
                }
            }
        }
        ResourceDescriptor::EventQueue(queue) => {
            if len < 32 {
                return Err(noct_io::error::Error::MemoryError as _);
            }

            if queue.is_empty() {
                input_needs_waiting = true;
            } else {
                qemu_log!("Got past checking!");

                let event = queue.get_raw().unwrap().serialize();

                slice[..event.len()].copy_from_slice(&event);
            }
        }
        ResourceDescriptor::FileStream(file_handle) => {
            let read_bytes = file_handle.read(slice)?;

            return Ok(read_bytes as usize);
        }
        _ => return Err(Error::InvalidHandle),
    }

    drop(lock);

    if input_needs_waiting {
        noct_sched::pause(ThreadWaitReason::InputEvent);
    }

    Ok(0)
}

pub fn write(fd: usize, data: usize, len: usize, _: usize, _: usize) -> Result<usize, Error> {
    // FIXME: VERIFY THE POINTER IS WITHIN USERSPACE AREA!

    let ptr = data as *const u8;
    let slice = unsafe { core::slice::from_raw_parts(ptr, len) };

    let process = &noct_sched::this_thread().process;

    let mut lock = process.resources.lock();

    // XXX: Or Error::NotFound?
    let fd_val = lock.find_mut(fd).ok_or(Error::InvalidHandle)?;

    // qemu_log!("write: fd {fd} -> {:?}", fd_val.res);

    match &mut fd_val.res {
        ResourceDescriptor::Null => return Ok(0),
        ResourceDescriptor::TerminalOutput => {
            noct_tty::WRITER
                .lock()
                .write_str(unsafe { str::from_utf8_unchecked(slice) })
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
