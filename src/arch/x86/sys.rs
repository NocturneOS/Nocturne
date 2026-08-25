use multiboot2::BootInformation;
use noct_logger::qemu_log;

unsafe extern "C" {
    // Defined in linker script src/arch/x86{,_64}/link.ld
    //
    // They are ZST (Zero sized types) because those symbols doesn't CONTAIN an address,
    // they are placed AT THESE ADDRESSES, we only have to take an address of these symbols.
    static IMAGE_VIRT_START: *const ();
    static IMAGE_VIRT_END: *const ();
}

pub fn init(boot: &BootInformation) {
    let kernel_start = unsafe { ((&IMAGE_VIRT_START) as *const *const ()).addr() };
    let kernel_end = unsafe { ((&IMAGE_VIRT_END) as *const *const ()).addr() };

    noct_sysinfo::info_mut().kernel_start = kernel_start;
    noct_sysinfo::info_mut().kernel_end = kernel_end;

    noct_sysinfo::info_mut().kernel_area_end = {
        let last_module = if let Some(mo) = boot.module_tags().last() {
            noct_spec::KERNEL_BASE + mo.end_address() as usize
        } else {
            kernel_end
        };

        core::cmp::max(last_module, boot.end_address())
    };

    qemu_log!("Kernel area ends at: {:#x?}", noct_sysinfo::info().kernel_area_end);
}
