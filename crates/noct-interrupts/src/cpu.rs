#[inline]
pub fn are_interrupts_enabled() -> bool {
    #[cfg(target_arch = "x86")]
    {
        use x86::current::eflags::EFlags;

        unsafe { x86::current::eflags::read() }.contains(EFlags::FLAGS_IF)
    }

    #[cfg(target_arch = "x86_64")]
    {
        use x86::current::rflags::RFlags;

        x86::current::rflags::read().contains(RFlags::FLAGS_IF)
    }
}

#[inline]
pub fn enable_interrupts() {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    unsafe {
        x86::irq::enable()
    };
}

#[inline]
pub fn disable_interrupts() {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    unsafe {
        x86::irq::disable()
    };
}

pub fn get_interrupt_state() -> bool {
    are_interrupts_enabled()
}

pub fn set_interrupt_state(enabled: bool) {
    if enabled {
        enable_interrupts();
    } else {
        disable_interrupts();
    }
}