use core::alloc::Layout;

#[cfg(target_arch = "x86")]
pub(super) struct ArchitectureSpecificRegion {
    fxsave_region: *mut u8,
}

unsafe impl Sync for ArchitectureSpecificRegion {}
unsafe impl Send for ArchitectureSpecificRegion {}

impl ArchitectureSpecificRegion {
    pub fn new() -> Self {
        Self {
            fxsave_region: unsafe {
                alloc::alloc::alloc_zeroed(Layout::from_size_align_unchecked(512, 16))
            },
        }
    }
}

impl Drop for ArchitectureSpecificRegion {
    fn drop(&mut self) {
        unsafe {
            alloc::alloc::dealloc(
                self.fxsave_region,
                Layout::from_size_align_unchecked(512, 16),
            )
        };
    }
}
