unsafe extern "C" {
    // Defined in linker script src/arch/x86/link.ld
    // They are ZST (Zero sized types) because those symbols doesn't CONTAIN an address,
    // they are placed AT THESE ADDRESSES, we only have to take an address of these symbols.
    static IMAGE_VIRT_START: *const ();
    static IMAGE_VIRT_END: *const ();
}

pub fn init() {
    crate::sys::info::info_mut().kernel_start =
        unsafe { ((&IMAGE_VIRT_START) as *const *const ()).addr() };
    crate::sys::info::info_mut().kernel_end =
        unsafe { ((&IMAGE_VIRT_END) as *const *const ()).addr() };
}
