use noct_cpu::CPURegisters;
use noct_logger::qemu_log;

mod debug;
mod exit;

pub type SyscallHandler = fn(usize, usize, usize, usize, usize) -> Option<usize>;

const SYSCALL_HANDLERS: &[SyscallHandler] = &[
    // Dummy comment to prevent rustfmt onelining the array
    debug::debug,  // 0
    debug::reg_debug,  // 1
    exit::exit,  // 2
    exit::process_exit,  // 3
];

pub fn syscall_handler(regs: &mut CPURegisters) {
    cfg_if::cfg_if! {
        if #[cfg(target_arch = "x86")] {
            let nr = regs.eax as usize;

            let arg1 = regs.ebx as usize;
            let arg2 = regs.ecx as usize;
            let arg3 = regs.edx as usize;
            let arg4 = regs.esi as usize;
            let arg5 = regs.edi as usize;
        } else if #[cfg(target_arch = "x86_64")] {
            let nr = regs.rax as usize;

            let arg1 = regs.rbx as usize;
            let arg2 = regs.rcx as usize;
            let arg3 = regs.rdx as usize;
            let arg4 = regs.rsi as usize;
            let arg5 = regs.rdi as usize;
        }
    }

    // qemu_log!("System call!");

    if let Some(handler) = SYSCALL_HANDLERS.get(nr) {
        let result = handler(arg1, arg2, arg3, arg4, arg5);

        if let Some(r) = result {
            #[cfg(target_arch = "x86")]
            {
                regs.eax = r as u32;
            }
            #[cfg(target_arch = "x86_64")]
            {
                regs.rax = r as u64;
            }
        }
    }
}

pub fn init() {
    noct_interrupts::handler::register_interrupt_handler(0x80, syscall_handler);
}
