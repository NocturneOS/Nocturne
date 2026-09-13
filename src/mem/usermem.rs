/// Verifies that passed pointer really came from the user space.
pub fn verify_ptr_mut<T>(addr: usize) -> Option<*mut T> {
    if addr == 0 {
        return None;
    }

    // Kernel area starts in the kernel base and ends in kernel heap's end.
    let kernel_area = noct_spec::KERNEL_BASE..noct_mem::heap::heap_bounds().end;

    if kernel_area.contains(&addr) {
        return None;
    }

    Some(addr as *mut T)
}

pub fn verify_ptr<T>(addr: usize) -> Option<*const T> {
    verify_ptr_mut(addr).map(|x| x as *const T)
}
