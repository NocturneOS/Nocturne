#[inline]
pub fn halt() {
    unsafe {
        x86::halt();
    }
}
