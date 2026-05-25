use noct_cpu::CPURegisters;
use noct_logger::qemu_log;

mod debug;

pub type SyscallHandler = fn(usize, usize, usize, usize, usize) -> Option<usize>;

const SYSCALL_HANDLERS: &[SyscallHandler] = &[
    debug::debug
];

pub fn syscall_handler(regs: &mut CPURegisters) {
    let nr = regs.eax as usize;

    let arg1 = regs.ebx as usize;
    let arg2 = regs.ecx as usize;
    let arg3 = regs.edx as usize;
    let arg4 = regs.esi as usize;
    let arg5 = regs.edi as usize;

    qemu_log!("System call!");
    
    if let Some(handler) = SYSCALL_HANDLERS.get(nr) {
        let result = handler(arg1, arg2, arg3, arg4, arg5);

        if let Some(r) = result {
            regs.eax = r as u32;
        }
    }
}

pub fn init() {
    noct_interrupts::handler::register_interrupt_handler(0x80, syscall_handler);
}