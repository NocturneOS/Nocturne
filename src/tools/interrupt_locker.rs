use crate::arch;

pub struct InterruptLocker {
    was_interruptful: bool
}

impl InterruptLocker {
    pub fn lock() -> Self {
        let was_interruptful = arch::are_interrupts_enabled();

        arch::disable_interrupts();

        Self {
            was_interruptful
        }
    }
}

impl Drop for InterruptLocker {
    fn drop(&mut self) {
        if self.was_interruptful {
            arch::enable_interrupts();
        }
    }
}