use core::sync::atomic::AtomicBool;

pub struct InterruptLocker {
    interrupt_state: bool,
}

impl InterruptLocker {
    pub fn lock() -> Self {
        let interrupt_state = noct_interrupts::cpu::get_interrupt_state();

        noct_interrupts::cpu::disable_interrupts();

        Self {
            interrupt_state,
        }
    }
}

impl Drop for InterruptLocker {
    fn drop(&mut self) {
        noct_interrupts::cpu::set_interrupt_state(self.interrupt_state);
    }
}
