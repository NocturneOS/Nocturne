use crate::{
    arch::{halt_forever, CPURegisters},
    interrupts::handler::register_interrupt_handler,
    qemu_println,
};

fn division_by_zero(regs: &mut CPURegisters) {
    qemu_println!("Division by zero...");

    common_fault_entry(regs);
}

fn general_protection_fault(regs: &mut CPURegisters) {
    qemu_println!("General protection fault...");

    common_fault_entry(regs);
}

fn page_fault(regs: &mut CPURegisters) {
    qemu_println!("Page fault...");

    common_fault_entry(regs);
}

fn sse_fault(regs: &mut CPURegisters) {
    qemu_println!("SSE fault...");

    common_fault_entry(regs);
}

fn common_fault_entry(regs: &mut CPURegisters) {
    qemu_println!("{:x?}", regs);

    halt_forever();
}


pub fn register_exceptions() {
    register_interrupt_handler(0, division_by_zero);
    register_interrupt_handler(13, general_protection_fault);
    register_interrupt_handler(14, page_fault);
    register_interrupt_handler(19, sse_fault);
}
