#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use core::sync::atomic::AtomicPtr;
use core::{alloc::Layout, arch::asm};

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[repr(C)]
pub struct ArchitectureSpecificRegion {
    pub(super) fxsave_region: AtomicPtr<u8>,
    pub(super) tss_kernel_stack: AtomicPtr<u8>,
}

const TSS_KERNEL_STACK_SIZE: usize = 0x100;

impl ArchitectureSpecificRegion {
    pub fn new() -> Self {
        let fxsave_region =
            unsafe { alloc::alloc::alloc_zeroed(Layout::from_size_align_unchecked(512, 16)) };

        let tss_kernel_stack =
            unsafe { alloc::alloc::alloc_zeroed(Layout::from_size_align_unchecked(TSS_KERNEL_STACK_SIZE, 16)) };

        unsafe {
            asm!("fxsave ({})", in(reg) fxsave_region.addr(), options(att_syntax, nostack));
        }

        Self { 
            fxsave_region: fxsave_region.into(),
            tss_kernel_stack: unsafe { tss_kernel_stack.byte_add(TSS_KERNEL_STACK_SIZE) }.into()
        }
    }

    pub fn with_tss_stack(stack_pointer: usize) -> Self {
        let fxsave_region =
            unsafe { alloc::alloc::alloc_zeroed(Layout::from_size_align_unchecked(512, 16)) };

        unsafe {
            asm!("fxsave ({})", in(reg) fxsave_region.addr(), options(att_syntax, nostack));
        }

        Self { 
            fxsave_region: fxsave_region.into(),
            tss_kernel_stack: unsafe { stack_pointer as *mut u8 }.into()
        }
    }
}

impl Drop for ArchitectureSpecificRegion {
    fn drop(&mut self) {
        unsafe {
            alloc::alloc::dealloc(
                self.fxsave_region.load(core::sync::atomic::Ordering::SeqCst),
                Layout::from_size_align_unchecked(512, 16),
            );

            alloc::alloc::dealloc(
                self.tss_kernel_stack.load(core::sync::atomic::Ordering::SeqCst).byte_sub(TSS_KERNEL_STACK_SIZE),
                Layout::from_size_align_unchecked(TSS_KERNEL_STACK_SIZE, 16),
            )
        };
    }
}
