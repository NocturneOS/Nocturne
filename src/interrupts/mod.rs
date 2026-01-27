use lazy_static::lazy_static;
use spin::RwLock;

use crate::tools::pseudosync::PseudoSync;

pub mod handler;

struct ICStore {
    ic: Option<&'static dyn InterruptController>,
}

impl ICStore {
    pub const fn new() -> Self {
        Self { ic: None }
    }

    pub fn eoi(&self, interrupt_nr: u8) {
        if let Some(ic) = self.ic {
            ic.eoi(interrupt_nr);
        }
    }
}

unsafe impl Send for ICStore {}
unsafe impl Sync for ICStore {}

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
