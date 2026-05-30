use noct_boot::BootInfo;
use noct_multiboot::MultibootModule;

unsafe extern "C" {
    // Defined in linker script src/arch/x86/link.ld
    //
    // They are ZST (Zero sized types) because those symbols doesn't CONTAIN an address,
    // they are placed AT THESE ADDRESSES, we only have to take an address of these symbols.
    static IMAGE_VIRT_START: *const ();
    static IMAGE_VIRT_END: *const ();
}

pub fn init(boot: &impl BootInfo<ModuleType = MultibootModule>) {
    let kernel_start = unsafe { ((&IMAGE_VIRT_START) as *const *const ()).addr() };
    let kernel_end = unsafe { ((&IMAGE_VIRT_END) as *const *const ()).addr() };

    noct_sysinfo::info_mut().kernel_start = kernel_start;
    noct_sysinfo::info_mut().kernel_end = kernel_end;

    noct_sysinfo::info_mut().kernel_area_end = {
        if let Some(mo) = boot.modules().last() {
            use noct_boot::Module;

            noct_spec::KERNEL_BASE + mo.end()
        } else {
            kernel_end
        }
    };
}
