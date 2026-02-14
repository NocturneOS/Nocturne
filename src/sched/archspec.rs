#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use core::sync::atomic::AtomicPtr;
use core::{alloc::Layout, arch::asm};

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[repr(C)]
pub struct ArchitectureSpecificRegion {
    fxsave_region: AtomicPtr<u8>,
}

impl ArchitectureSpecificRegion {
    pub fn new() -> Self {
        let fxsave_region =
            unsafe { alloc::alloc::alloc_zeroed(Layout::from_size_align_unchecked(512, 16)) };

        unsafe {
            asm!("fxsave ({})", in(reg) fxsave_region.addr(), options(att_syntax, nostack));
        }

        Self { fxsave_region: fxsave_region.into() }
    }
}

impl Drop for ArchitectureSpecificRegion {
    fn drop(&mut self) {
        unsafe {
            alloc::alloc::dealloc(
                self.fxsave_region.load(core::sync::atomic::Ordering::SeqCst),
                Layout::from_size_align_unchecked(512, 16),
            )
        };
    }
}
