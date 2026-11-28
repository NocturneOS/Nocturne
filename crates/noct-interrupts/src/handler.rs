use core::sync::atomic::{AtomicPtr, Ordering};

use crate::eoi;

use noct_cpu::CPURegisters;
use noct_sync::pseudosync::PseudoSync;

pub type InterruptCallback = extern "C" fn(&mut CPURegisters) -> ();

// static INTERRUPT_VECTORS: PseudoSync<[Option<InterruptCallback>; 256]> =
//     unsafe { core::mem::zeroed() };

static INTERRUPT_VECTORS: [AtomicPtr<InterruptCallback>; 256] = unsafe { core::mem::zeroed() };

#[unsafe(no_mangle)]
pub unsafe extern "C" fn isr_handler(mut regs: CPURegisters) {
    interrupt_handler(&mut regs);
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn irq_handler(regs: &mut CPURegisters) {
    // Send EOI.
    eoi(regs.int_num as _);

    interrupt_handler(regs);
}

pub fn register_interrupt_handler(int_nr: u8, callback: InterruptCallback) {
    INTERRUPT_VECTORS[int_nr as usize].store(callback as _, Ordering::Release);

    // (unsafe { INTERRUPT_VECTORS.pseudo_lock() })[int_nr as usize] = Some(callback);
}

pub fn unregister_interrupt_handler(int_nr: u8) {
    INTERRUPT_VECTORS[int_nr as usize].store(core::ptr::null_mut(), Ordering::Release);

    // (unsafe { INTERRUPT_VECTORS.pseudo_lock() })[int_nr as usize] = None;
}

pub fn interrupt_handler(regs: &mut CPURegisters) {
    let interrupt_num = regs.int_num as usize;

    let iv = INTERRUPT_VECTORS.get(interrupt_num).map(|x| unsafe {
        core::mem::transmute::<_, extern "C" fn(&mut CPURegisters)>(x.load(Ordering::Relaxed))
    });
    // .copied();
    // .flatten();

    if let Some(iv) = iv {
        iv(regs);
    }
}
