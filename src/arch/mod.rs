use ::x86 as _x86;

pub mod x86;

#[inline]
pub fn halt() {
    #[cfg(target_arch = "x86")]
    unsafe {
        _x86::halt();
    }
}

#[inline]
pub fn halt_forever() -> ! {
    #[cfg(target_arch = "x86")]
    unsafe {
        _x86::irq::disable();
        halt();
    }

    loop {}
}