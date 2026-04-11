use crate::InterruptController;

pub struct ICStore {
    pub(crate) ic: Option<&'static dyn InterruptController>,
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