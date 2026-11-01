use core::slice::GetDisjointMutIndex;

/// Verifies that passed pointer really came from the user space.
pub fn verify_ptr_range_mut<T>(addr: usize, size: usize) -> Option<*mut T> {
    if addr == 0 {
        return None;
    }

    let end = addr + size;

    // Kernel area starts in the kernel base and ends in kernel heap's end.
    let kernel_area = noct_spec::KERNEL_BASE..noct_mem::heap::heap_bounds().end;

    if kernel_area.is_overlapping(&(addr..end)) {
        return None;
    }

    Some(addr as *mut T)
}

pub fn verify_ptr_range<T>(addr: usize, len: usize) -> Option<*const T> {
    verify_ptr_range_mut(addr, len * core::mem::size_of::<T>()).map(|x| x as *const T)
}

pub fn verify_ptr_mut<T>(addr: usize) -> Option<*mut T> {
    verify_ptr_range_mut(addr, core::mem::size_of::<T>())
}

pub fn verify_ptr<T>(addr: usize) -> Option<*const T> {
    verify_ptr_range(addr, core::mem::size_of::<T>()).map(|x| x as *const T)
}