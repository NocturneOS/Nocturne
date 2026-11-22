use noct_cpu::CPURegisters;
use noct_interrupts::handler::register_interrupt_handler;

const PIT_BASE_FREQ: u32 = 1193180;

extern "C" fn callback(_regs: &mut CPURegisters) {
    crate::time::tick();
}

#[allow(clippy::identity_op)]
pub fn init(frequency: u32) {
    let divisor = PIT_BASE_FREQ / frequency;

    let low_byte = (divisor & 0xff) as u8;
    let hi_byte = ((divisor >> 8) & 0xff) as u8;

    let control = (0b00 << 6) | (0b11 << 4) | (0b010 << 1);

    unsafe {
        x86::io::outb(0x43, control);

        x86::io::outb(0x40, low_byte);
        x86::io::outb(0x40, hi_byte);
    }

    noct_time::systemclock::set_timer_frequency(frequency as _);

    register_interrupt_handler(0x20, callback);
}