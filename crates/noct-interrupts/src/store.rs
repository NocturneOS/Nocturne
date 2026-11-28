use spin::RwLock;

use crate::{InterruptController, cpu};

pub struct ICStore {
    ic: RwLock<Option<&'static dyn InterruptController>>,
}

impl Default for ICStore {
    fn default() -> Self {
        Self::new()
    }
}

impl ICStore {
    pub const fn new() -> Self {
        Self {
            ic: RwLock::new(None),
        }
    }

    pub fn set(&self, ic: &'static dyn InterruptController) {
        // Interrupts must be disabled while the write lock is held:
        // A timer IRQ could otherwise try to take the read lock
        // in `eoi()` and spin forever on the same CPU.
        let was_enabled = cpu::are_interrupts_enabled();

        if was_enabled {
            cpu::disable_interrupts();
        }

        *self.ic.write() = Some(ic);

        if was_enabled {
            cpu::enable_interrupts();
        }
    }

    pub fn eoi(&self, interrupt_nr: u8) {
        // Copy controller object so lock is released immediately.
        let ic = *self.ic.read();

        if let Some(ic) = ic {
            ic.eoi(interrupt_nr);
        }
    }
}
