use core::{ffi::CStr, fmt::Write as FmtWrite};

use alloc::borrow::ToOwned;
use noct_descriptor::ResourceDescriptor;
use noct_fsman::handles::file::FileOpenMode;
use noct_io::{Read, Seek, SeekOffset, Write};
use noct_logger::qemu_log;

use bitflags::bitflags;
use noct_sched::thread::ThreadWaitReason;

bitflags! {
    #[derive(Debug, Clone, Copy)]
    pub struct OpenFlags: u32 {
        // First flags are copied from noct_fsman::FileOpenFlags
        const Directory = 1 << 5;
    }
}

pub fn open(path: usize, mode: usize, _: usize, _: usize, _: usize) -> Option<usize> {
    // TODO: Sanitize that.
    // TODO: Set error on utf8 encoding failure
    let path = unsafe { CStr::from_ptr(path as *const core::ffi::c_char) }
        .to_str()
        .map(|path| path.to_owned());

    let path = match path {
        Ok(path) => path,
        Err(e) => {
            qemu_log!("open: Error while decoding UTF-8 path: {e:?}");

            noct_sched::set_error(noct_io::error::Error::InvalidPath as _);

            return None;
        }
    };

    let flags = OpenFlags::from_bits_truncate(mode as _);

    let handle = if flags.contains(OpenFlags::Directory) {
        let dir = match noct_fs::open_directory(&path) {
            Ok(dh) => dh,
            Err(e) => {
                noct_sched::set_error(e as _);

                return Some((-1_isize) as usize);
            }
        };

        ResourceDescriptor::DirectoryHandle(dir)
    } else {
        let fh = match noct_fs::open_file(&path, FileOpenMode::from_bits_truncate(mode as _)) {
            Ok(fh) => fh,
            Err(e) => {
                noct_sched::set_error(e as _);

                return Some((-1_isize) as usize);
            }
        };

        ResourceDescriptor::FileStream(fh)
    };

    let process = &noct_sched::this_thread().process;

    let mut reslock = process.resources.lock();

    let descr = reslock.make(handle);

    Some(descr.id())
}

pub fn close(fd: usize, _: usize, _: usize, _: usize, _: usize) -> Option<usize> {
    let process = &noct_sched::this_thread().process;

    let mut reslock = process.resources.lock();

    reslock.close(fd);

    None
}

pub fn read(fd: usize, data: usize, len: usize, _: usize, _: usize) -> Option<usize> {
    // FIXME: VERIFY THE POINTER IS WITHIN USERSPACE AREA!

    let ptr = data as *mut u8;
    let slice = unsafe { core::slice::from_raw_parts_mut(ptr, len) };

    // Test-fill that. If this call causes an exception (due to Page Fault / GPF) it will kill whole process.
    slice.fill(0);

    let process = &noct_sched::this_thread().process;

    let mut lock = process.resources.lock();

    let fd_val = lock.find_mut(fd)?;

    qemu_log!("read: fd {fd} -> {:?}", fd_val.res);

    let mut input_needs_waiting = false;

    match &mut fd_val.res {
        ResourceDescriptor::Null => return Some(0),
        ResourceDescriptor::TerminalInput => {
            let ifd = noct_tty::input::input_fd();

            // Kernel TTY is always in kernel process.
            let kproc = noct_sched::this().kernel_process().clone();

            let mut kres = kproc.resources.lock();

            let evq = kres
                .find_mut(ifd)?
                .res
                .as_event_queue_mut()
                .expect("Input FD is not an EventQueue!");

            match noct_tty::input::get_char(evq) {
                Some(0) | None => {
                    input_needs_waiting = true;
                }
                Some(ch) => {
                    slice[0] = ch;

                    return Some(1);
                }
            }
        }
        ResourceDescriptor::EventQueue(queue) => {
            if len < 32 {
                noct_sched::set_error(noct_io::error::Error::MemoryError as _);

                return None;
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
            let value = file_handle.read(slice);

            match value {
                Err(e) => noct_sched::set_error(e as _),
                Ok(read_bytes) => return Some(read_bytes as _),
            }
        }
        _ => {
            noct_sched::set_error(noct_io::error::Error::InvalidHandle as _)
        }
    }

    drop(lock);

    if input_needs_waiting {
        noct_sched::pause(ThreadWaitReason::InputEvent);
    }

    Some(0)
}

pub fn write(fd: usize, data: usize, len: usize, _: usize, _: usize) -> Option<usize> {
    // FIXME: VERIFY THE POINTER IS WITHIN USERSPACE AREA!

    let ptr = data as *const u8;
    let slice = unsafe { core::slice::from_raw_parts(ptr, len) };

    let process = &noct_sched::this_thread().process;

    let mut lock = process.resources.lock();

    let fd_val = lock.find_mut(fd)?;

    qemu_log!("write: fd {fd} -> {:?}", fd_val.res);

    match &mut fd_val.res {
        ResourceDescriptor::Null => return Some(0),
        ResourceDescriptor::TerminalOutput => {
            let result = noct_tty::WRITER
                .lock()
                .write_str(unsafe { str::from_utf8_unchecked(slice) });

            if let Err(_) = result {
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
        ResourceDescriptor::VideoLock(v) => {
            v.write(slice);

            return Some(slice.len());
        }
        _ => {
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
        ResourceDescriptor::VideoLock(v) => {
            match whence {
                0 => v.seek(offset as _),
                1 => v.seek(v.offset() + offset),
                2 => v.seek(v.buffer_len() - offset),
                _ => {
                    noct_sched::set_error(noct_io::error::Error::InvalidSeek as _);

                    return None;
                }
            }
        }
        _ => {
            noct_sched::set_error(noct_io::error::Error::InvalidHandle as _)
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
        ResourceDescriptor::FileStream(file_handle) => {
            let value = file_handle.seek(SeekOffset::Current(0));

            match value {
                Err(e) => noct_sched::set_error(e as _),
                Ok(position) => return Some(position as _),
            }
        }
        ResourceDescriptor::VideoLock(v) => {
            return Some(v.offset());
        }
        _ => {
            noct_sched::set_error(noct_io::error::Error::InvalidHandle as _)
        }
    }

    None
}

pub fn flush(fd: usize, _: usize, _: usize, _: usize, _: usize) -> Option<usize> {
    let process = &noct_sched::this_thread().process;

    let mut lock = process.resources.lock();

    let fd_val = lock.find_mut(fd)?;

    match &mut fd_val.res {
        ResourceDescriptor::Null => return Some(0),
        ResourceDescriptor::TerminalOutput => {
            noct_tty::WRITER.try_lock()?.flush();
            return Some(0);
        }
        ResourceDescriptor::FileStream(file_handle) => {
            let value = file_handle.flush();

            match value {
                Err(e) => noct_sched::set_error(e as _),
                Ok(_) => return Some(0),
            }
        }
        _ => {
            noct_sched::set_error(noct_io::error::Error::InvalidHandle as _)
        }
    }

    None
}