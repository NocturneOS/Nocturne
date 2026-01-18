use spin::RwLock;

#[cfg(target_arch = "x86")]
use crate::arch::x86::CPURegisters;

use crate::interrupts::CURRENT_INTERRUPT_CONTROLLER;

pub type InterruptCallback = fn(&mut CPURegisters) -> ();

static INTERRUPT_VECTORS: RwLock<[Option<InterruptCallback>; 256]> = unsafe { core::mem::zeroed() };

#[unsafe(no_mangle)]
pub unsafe extern "C" fn isr_handler(mut regs: CPURegisters) {
    interrupt_handler(&mut regs);
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn irq_handler(mut regs: CPURegisters) {
    interrupt_handler(&mut regs);

    // Send EOI.
    CURRENT_INTERRUPT_CONTROLLER.read().eoi(regs.int_num as _);
}

pub fn register_interrupt_handler(int_nr: u8, callback: InterruptCallback) {
    INTERRUPT_VECTORS.write()[int_nr as usize] = Some(callback);
}

pub fn unregister_interrupt_handler(int_nr: u8) {
    INTERRUPT_VECTORS.write()[int_nr as usize] = None;
}

pub fn interrupt_handler(regs: &mut CPURegisters) {
    let interrupt_num = regs.int_num as usize;

    let iv = INTERRUPT_VECTORS
        .read()
        .get(interrupt_num)
        .map(|x| *x)
        .flatten();

    if let Some(iv) = iv {
        iv(regs);
    }
}
