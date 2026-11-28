use core::sync::atomic::{AtomicPtr, Ordering};

use crate::eoi;

use noct_cpu::CPURegisters;

pub type InterruptCallback = extern "C" fn(&mut CPURegisters) -> ();

/// Interrupt vector array of 256 vectors.
static INTERRUPT_VECTORS: [AtomicPtr<()>; 256] =
    [const { AtomicPtr::new(core::ptr::null_mut()) }; 256];

/// Entry point for CPU exceptions.
///
/// # Safety
/// Must only be called from the assembly interrupt stub.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn isr_handler(mut regs: CPURegisters) {
    interrupt_handler(&mut regs);
}

/// Entry point for hardware IRQs.
///
/// # Safety
/// Must only be called from the assembly interrupt stub
#[unsafe(no_mangle)]
pub unsafe extern "C" fn irq_handler(regs: &mut CPURegisters) {
    // Send EOI.
    eoi(regs.int_num as _);

    interrupt_handler(regs);
}

pub fn register_interrupt_handler(int_nr: u8, callback: InterruptCallback) {
    INTERRUPT_VECTORS[int_nr as usize].store(callback as *mut (), Ordering::Release);
}

pub fn unregister_interrupt_handler(int_nr: u8) {
    INTERRUPT_VECTORS[int_nr as usize].store(core::ptr::null_mut(), Ordering::Release);
}

pub fn interrupt_handler(regs: &mut CPURegisters) {
    let interrupt_num = regs.int_num as usize;

    let Some(vector) = INTERRUPT_VECTORS.get(interrupt_num) else {
        return;
    };

    let callback = vector.load(Ordering::Acquire);

    if callback.is_null() {
        return;
    }

    // SAFETY: It's obvious that only `InterruptCallback` are only stored there. 
    let callback: InterruptCallback = unsafe { core::mem::transmute(callback) };

    callback(regs);
}
