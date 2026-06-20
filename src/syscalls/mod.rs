use noct_cpu::CPURegisters;

mod debug;
mod error;
mod exit;
mod waitpid;

pub type SyscallHandler = fn(usize, usize, usize, usize, usize) -> Option<usize>;

const SYSCALL_HANDLERS: &[SyscallHandler] = &[
    // Dummy comment to prevent rustfmt onelining the array
    debug::debug,       // 0
    debug::reg_debug,   // 1
    exit::exit,         // 2
    exit::process_exit, // 3
    error::geterror,    // 4
    waitpid::waitpid,   // 5
];

#[unsafe(no_mangle)]
pub extern "C" fn syscall_handler(regs: &mut CPURegisters) {
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

            let arg1 = regs.rdi as usize;
            let arg2 = regs.rsi as usize;
            let arg3 = regs.rdx as usize;
            let arg4 = regs.r10 as usize;
            let arg5 = regs.r8 as usize;
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

unsafe extern "C" {
    // Defined in src/arch/x86_64/asm/syscall.s
    fn __syscall_handler64();
}

pub fn init() {
    #[cfg(target_arch = "x86_64")]
    {
        use noct_cpu::x86_64::VirtAddr;
        use noct_cpu::x86_64::registers::control::Efer;
        use noct_cpu::x86_64::registers::model_specific::{LStar, SFMask};
        use noct_cpu::x86_64::registers::control::EferFlags;
        use noct_cpu::x86_64::registers::rflags::RFlags;

        // Enable `syscall/sysret` support
        unsafe {
            Efer::update(|x| {

                *x |= EferFlags::SYSTEM_CALL_EXTENSIONS;
            })
        };

        // RFLAGS on system call
        SFMask::update(|x| *x |= RFlags::INTERRUPT_FLAG);

        // Point CPU where lowlevel syscall handler is
        LStar::write(VirtAddr::new(__syscall_handler64 as *const () as _));
    }

    // 32-bit backward compatibility
    noct_interrupts::handler::register_interrupt_handler(0x80, syscall_handler);
}
