use spin::RwLock;

pub mod handler;

struct ICStore {
    ic: Option<&'static dyn InterruptController>
}

impl ICStore {
    pub const fn new() -> Self {
        Self {
            ic: None
        }
    }

    pub fn eoi(&self, interrupt_nr: u8) {
        if let Some(ic) = self.ic {
            ic.eoi(interrupt_nr);
        }
    }
}

unsafe impl Send for ICStore {}
unsafe impl Sync for ICStore {}

static CURRENT_INTERRUPT_CONTROLLER: RwLock<ICStore> = RwLock::new(ICStore::new());

pub trait InterruptController {
    fn eoi(&self, interrupt_nr: u8);
}

pub fn set_interrupt_controller(ic: &'static dyn InterruptController) {
    CURRENT_INTERRUPT_CONTROLLER.write().ic = Some(ic);
}

pub fn eoi(interrupt_nr: u8) {
    CURRENT_INTERRUPT_CONTROLLER.read().eoi(interrupt_nr);
}