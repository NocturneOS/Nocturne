#![no_std]

extern crate alloc;

use crate::store::ICStore;

pub mod handler;
pub mod store;

pub mod cpu;

static CURRENT_INTERRUPT_CONTROLLER: ICStore = ICStore::new();

pub trait InterruptController: Sync {
    fn eoi(&self, interrupt_nr: u8);
}

pub fn set_interrupt_controller(ic: &'static dyn InterruptController) {
    CURRENT_INTERRUPT_CONTROLLER.set(ic);
}

pub fn eoi(interrupt_nr: u8) {
    CURRENT_INTERRUPT_CONTROLLER.eoi(interrupt_nr);
}
