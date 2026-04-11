#![no_std]

extern crate alloc;

use lazy_static::lazy_static;
use noct_sync::pseudosync::PseudoSync;

use crate::store::ICStore;

pub mod store;
pub mod handler;

pub mod cpu;

lazy_static! {
    static ref CURRENT_INTERRUPT_CONTROLLER: PseudoSync<ICStore> = PseudoSync::new(ICStore::new());
}

pub trait InterruptController {
    fn eoi(&self, interrupt_nr: u8);
}

pub fn set_interrupt_controller(ic: &'static dyn InterruptController) {
    unsafe { CURRENT_INTERRUPT_CONTROLLER.get_mut().ic = Some(ic) };
}

pub fn eoi(interrupt_nr: u8) {
    CURRENT_INTERRUPT_CONTROLLER.get().eoi(interrupt_nr);
}
