use noct_cpu::CPURegisters;
use noct_interrupts::handler::register_interrupt_handler;
use noct_logger::qemu_log;
use x86::io::inb;

use crate::{
    PS2_STATE_REG,
    controller::{self, read_configuration_byte, write_configuration_byte},
};

// TODO: Make it more Rust-like: with Result<T, E>.
#[unsafe(no_mangle)]
pub extern "C" fn init() {
    let mut stat: u8;

    unsafe { controller::write(0xf4) };
    stat = controller::read();

    if stat != 0xfa {
        qemu_log!("Keyboard error: Enable fail");
        return;
    }

    unsafe { controller::write(0xf0) };
    stat = controller::read();

    if stat != 0xfa {
        qemu_log!("Keyboard error: Scancode set fail");
        return;
    }

    unsafe { controller::write(0) };
    stat = controller::read();

    if stat != 0xfa {
        qemu_log!("Keyboard error: Zero fail");
        return;
    }

    let _scancode = controller::read() & 0b11;

    unsafe { controller::write(0xf3) };
    stat = controller::read();

    if stat != 0xfa {
        qemu_log!("Keyboard error: Repeat fail");
        return;
    }

    unsafe { controller::write(0) };
    stat = controller::read();

    if stat != 0xfa {
        qemu_log!("Keyboard error: Zero fail (phase 2)");
        return;
    }

    let conf = read_configuration_byte();

    qemu_log!("Configuration byte is: {conf:b}");

    unsafe { write_configuration_byte(conf | 0b0100_0001) };
}

pub extern "C" fn keyboard_handler(_regs: &mut CPURegisters) {
    let kbdstatus = unsafe { inb(PS2_STATE_REG) };

    if (kbdstatus & 0x01) != 0 {
        let scancode = controller::read();

        let code = scancode & 0x7f;
        let pressed = (scancode & 0x80) == 0;
        
        qemu_log!("Keyboard event! Sending it...");

        // noct_input_dispatcher::deliver_event(noct_input_dispatcher::event::InputEvent::Key { code, pressed });

        qemu_log!("{scancode} (code: {code}, pressed: {pressed})");
    }
}

#[unsafe(no_mangle)]
pub fn install_irq() {
    register_interrupt_handler(0x21, keyboard_handler);

    qemu_log!("PS/2 keyboard interrupt installed!");
}
