#[cfg(target_arch = "x86")]
use crate::arch::x86::CPURegisters;

use crate::qemu_println;

#[unsafe(no_mangle)]
pub unsafe extern "C" fn isr_handler(mut regs: CPURegisters) {
    interrupt_handler(&mut regs);
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn irq_handler(mut regs: CPURegisters) {
    interrupt_handler(&mut regs);
    
    // Send EOI.
}

pub fn interrupt_handler(regs: &mut CPURegisters) {
    qemu_println!("INTERRUPT!");
}