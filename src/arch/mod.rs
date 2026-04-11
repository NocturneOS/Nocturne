use cfg_if::cfg_if;

use ::x86 as _x86;

cfg_if! {
    if #[cfg(any(target_arch = "x86"))] {
        pub mod x86;
        pub use x86::mem;        
    } else if #[cfg(target_arch = "x86_64")] {
        pub mod x86;
        pub mod x86_64;
        pub use x86_64::mem;
    }
}

#[inline]
pub fn are_interrupts_enabled() -> bool {
    #[cfg(target_arch = "x86")]
    {
        use ::x86::current::eflags::EFlags;

        unsafe { _x86::current::eflags::read() }.contains(EFlags::FLAGS_IF)
    }

    #[cfg(target_arch = "x86_64")]
    {
        use ::x86::current::rflags::RFlags;

        unsafe { _x86::current::rflags::read() }.contains(RFlags::FLAGS_IF)
    }
}

#[inline]
pub fn enable_interrupts() {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    unsafe {
        _x86::irq::enable()
    };
}

#[inline]
pub fn disable_interrupts() {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    unsafe {
        _x86::irq::disable()
    };
}

#[inline]
pub fn halt() {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    unsafe {
        _x86::halt();
    }
}

#[inline]
pub fn halt_forever() -> ! {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    unsafe {
        _x86::irq::disable();
        halt();
    }

    loop {}
}

#[inline]
pub fn get_page_size() -> usize {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    return mem::paging::PAGE_SIZE;

    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
    compile_error!(
        "No page size is specified for architecture {:#?}",
        env!("CARGO_CFG_TARGET_ARCH")
    );
}
