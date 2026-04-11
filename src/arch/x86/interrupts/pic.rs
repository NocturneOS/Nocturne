use noct_interrupts::InterruptController;
use x86::io::outb;

struct PIC;

static PIC_ENTITY: PIC = PIC;

impl InterruptController for PIC {
    fn eoi(&self, interrupt_nr: u8) {
        if interrupt_nr >= 0x28 {
            unsafe { outb(0xA0, 0x20) };
        }

        unsafe { outb(0x20, 0x20) };
    }
}

pub fn init() {
    unsafe {
        outb(0x20, 0x11);
        outb(0xA0, 0x11);

        outb(0x21, 0x20);
        outb(0xA1, 0x28);

        outb(0x21, 0x04);
        outb(0xA1, 0x02);

        outb(0x21, 0x01);
        outb(0xA1, 0x01);

        outb(0x21, 0x0);
        outb(0xA1, 0x0);
    }

    noct_interrupts::set_interrupt_controller(&PIC_ENTITY);
}

pub fn disable() {
    unsafe {
        outb(0xA0, 0x11);
        outb(0x20, 0x10);

        outb(0xA1, 0x20);
        outb(0x21, 0x28);

        outb(0xA1, 0x2);
        outb(0x21, 0x4);

        outb(0xA1, 0x01);
        outb(0x21, 0x01);

        outb(0xA1, 0xFF);
        outb(0x21, 0xFF);
    }
}
