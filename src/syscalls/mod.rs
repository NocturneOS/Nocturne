use noct_cpu::CPURegisters;
use noct_logger::qemu_log;

mod debug;
mod error;
mod event;
mod exit;
mod fd;
mod mem;
mod print;
mod proc;
mod time;
mod video;

pub type SyscallHandler = fn(usize, usize, usize, usize, usize) -> Option<usize>;

#[rustfmt::skip]
const SYSCALL_HANDLERS: &[SyscallHandler] = &[
    debug::debug,           // 0 - TO REMOVE?
    debug::reg_debug,       // 1 - TO REMOVE?

    exit::exit,             // 2
    exit::process_exit,     // 3
    
    error::geterror,        // 4
    
    proc::waitpid,          // 5
    
    print::write_tty,       // 6 - TO REMOVE?

    fd::open,               // 7
    fd::close,              // 8
    fd::read,               // 9
    fd::write,              // 10
    fd::seek,               // 11
    fd::tell,               // 12

    mem::sbrk,              // 13

    event::open,            // 14

    fd::flush,              // 15

    time::time,             // 16
    time::sleep_millis,     // 17
    time::sleep_nanos,      // 18

    proc::yield_now,        // 19

    video::video_acquire,   // 20
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

    qemu_log!("System call!");

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
    } else {
        qemu_log!("Error: no syscall handle for id: 0x{nr:x}");
    }
}

// TODO: Is this definition and following initialization function should be in arch-specific crate (like `noct-cpu`)?
unsafe extern "C" {
    // Defined in src/arch/x86_64/asm/syscall.s
    fn __syscall_handler64();
}

pub fn init() {
    #[cfg(target_arch = "x86_64")]
    {
        use noct_cpu::x86_64::PrivilegeLevel;
        use noct_cpu::x86_64::VirtAddr;
        use noct_cpu::x86_64::registers::control::Efer;
        use noct_cpu::x86_64::registers::control::EferFlags;
        use noct_cpu::x86_64::registers::model_specific::{LStar, SFMask, Star};
        use noct_cpu::x86_64::registers::rflags::RFlags;
        use noct_cpu::x86_64::structures::gdt::SegmentSelector;
        use noct_logger::qemu_log;

        // Enable `syscall/sysret` support
        unsafe {
            Efer::update(|x| {
                *x |= EferFlags::SYSTEM_CALL_EXTENSIONS;
            })
        };

        // RFLAGS on system call
        qemu_log!("RFLAGS: {:x?}", SFMask::read());

        SFMask::update(|x| *x |= RFlags::INTERRUPT_FLAG);

        Star::write(
            SegmentSelector::new(4, PrivilegeLevel::Ring3),
            SegmentSelector::new(3, PrivilegeLevel::Ring3),
            SegmentSelector::new(1, PrivilegeLevel::Ring0),
            SegmentSelector::new(2, PrivilegeLevel::Ring0),
        )
        .unwrap();

        // Point CPU where lowlevel syscall handler is
        LStar::write(VirtAddr::new(__syscall_handler64 as *const () as _));
    }

    // 32-bit backward compatibility and common syscall entry for x86_32.
    noct_interrupts::handler::register_interrupt_handler(0x80, syscall_handler);
}
