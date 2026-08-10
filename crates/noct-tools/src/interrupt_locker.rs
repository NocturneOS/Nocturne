use core::sync::atomic::AtomicBool;

pub struct InterruptLocker {
    interrupt_state_enabled: bool,
}

impl InterruptLocker {
    pub fn lock() -> Self {
        let interrupt_state = noct_interrupts::cpu::are_interrupts_enabled();

        noct_interrupts::cpu::disable_interrupts();

        Self {
            interrupt_state_enabled: interrupt_state,
        }
    }
}

impl Drop for InterruptLocker {
    fn drop(&mut self) {
        if self.interrupt_state_enabled {
            noct_interrupts::cpu::enable_interrupts();
        }
    }
}
