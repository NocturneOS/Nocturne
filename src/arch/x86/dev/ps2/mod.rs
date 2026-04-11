use crate::qemu_log;

pub const PS2_DATA_PORT: u16 = 0x60;
pub const PS2_STATE_REG: u16 = 0x64;

pub mod controller;
pub mod keyboard;

pub fn init() {
    let (first_ok, second_ok) = controller::init();

    if first_ok {
        keyboard::init();
        keyboard::install_irq();
    }

    if second_ok {
        // mouse::init();
    }
}
