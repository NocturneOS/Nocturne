use ::x86 as _x86;

#[cfg(target_arch = "x86")]
pub mod x86;

pub fn enable_interrupts() {
    #[cfg(target_arch = "x86")]
    unsafe {
        _x86::irq::enable()
    };
}

pub fn disable_interrupts() {
    #[cfg(target_arch = "x86")]
    unsafe {
        _x86::irq::disable()
    };
}

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

#[inline]
pub fn get_page_size() -> usize {
    #[cfg(target_arch = "x86")]
    return x86::mem::paging::PAGE_SIZE;

    #[cfg(not(target_arch = "x86"))]
    compile_error!("No page size is specified for architecture {:#?}", env!("CARGO_CFG_TARGET_ARCH"));
}