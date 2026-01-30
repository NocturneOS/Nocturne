use ::x86 as _x86;

#[cfg(target_arch = "x86")]
pub mod x86;

#[cfg(target_arch = "x86")]
pub use x86::regs::CPURegisters;

#[inline]
pub fn are_interrupts_enabled() -> bool {
    #[cfg(target_arch = "x86")]
    {
        use ::x86::bits32::eflags::EFlags;

        unsafe { _x86::current::eflags::read() }.contains(EFlags::FLAGS_IF)
        // (unsafe { _x86::current::eflags::read().bits() } & EFlags::FLAGS_IF.bits()) != 0
    }
}

#[inline]
pub fn enable_interrupts() {
    #[cfg(target_arch = "x86")]
    unsafe {
        _x86::irq::enable()
    };
}

#[inline]
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
    compile_error!(
        "No page size is specified for architecture {:#?}",
        env!("CARGO_CFG_TARGET_ARCH")
    );
}
