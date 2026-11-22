use core::slice::GetDisjointMutIndex;

use alloc::{string::String, vec::Vec};
use noct_io::error::Error;

/// Verifies that passed pointer really came from the user space.
pub fn verify_ptr_range_mut<T>(addr: usize, size: usize) -> Option<*mut T> {
    if addr == 0 {
        return None;
    }

    let end = addr.checked_add(size)?;

    // Kernel area starts in the kernel base and ends in kernel heap's end.
    let kernel_area = noct_spec::KERNEL_BASE..noct_mem::heap::heap_bounds().end;

    if kernel_area.is_overlapping(&(addr..end)) {
        return None;
    }

    Some(addr as *mut T)
}

pub fn verify_ptr_range<T>(addr: usize, len: usize) -> Option<*const T> {
    let size = len.checked_mul(core::mem::size_of::<T>())?;

    verify_ptr_range_mut(addr, size).map(|x| x as *const T)
}

pub fn verify_ptr_mut<T>(addr: usize) -> Option<*mut T> {
    verify_ptr_range_mut(addr, core::mem::size_of::<T>())
}

pub fn verify_ptr<T>(addr: usize) -> Option<*const T> {
    verify_ptr_range(addr, core::mem::size_of::<T>()).map(|x| x as *const T)
}


/// Maximum accepted string length from user space, including the NUL terminator.
const MAX_STRING_LEN: usize = 4096;

/// Copies a NUL-terminated string from the calling process' address space.
/// Unlike `CStr::from_ptr`, this never scans further than [`MAX_PATH_LEN`] and
/// validates every byte before reading it, so a missing terminator can't make
/// the kernel walk into memory that doesn't belong to the caller.
pub fn copy_user_string(addr: usize) -> Result<String, Error> {
    let mut bytes = Vec::new();

    for offset in 0..MAX_STRING_LEN {
        let ptr = addr
            .checked_add(offset)
            .and_then(verify_ptr::<u8>)
            .ok_or(Error::MemoryError)?;

        match unsafe { *ptr } {
            0 => return String::from_utf8(bytes).map_err(|_| Error::InvalidPath),
            byte => bytes.push(byte),
        }
    }

    // The string is not terminated within the allowed limit.
    Err(Error::InvalidPath)
}