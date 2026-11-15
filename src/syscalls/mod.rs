use noct_cpu::CPURegisters;
use noct_logger::qemu_log;

mod audio;
mod debug;
mod env;
mod error;
mod event;
mod exit;
mod dir;
mod fd;
mod mem;
mod proc;
mod rand;
mod thread;
mod time;
mod video;

pub type SyscallResult = Result<usize, noct_io::error::Error>;
pub type SyscallHandler = fn(usize, usize, usize, usize, usize) -> SyscallResult;

#[rustfmt::skip]
const SYSCALL_HANDLERS: &[SyscallHandler] = &[
    exit::exit,             // 0
    exit::process_exit,     // 1
    
    error::geterror,        // 2
    
    proc::waitpid,          // 3
    
    fd::open,               // 4
    fd::close,              // 5
    fd::read,               // 6
    fd::write,              // 7
    fd::seek,               // 8
    fd::tell,               // 9

    mem::sbrk,              // 10

    event::open,            // 11

    fd::flush,              // 12

    time::sleep_millis,     // 13
    time::sleep_nanos,      // 14

    proc::yield_now,        // 15

    video::video_acquire,   // 16

    env::getcwd,            // 17

    env::chdir,             // 18

    proc::run,              // 19

    mem::mrequest,          // 20
    mem::mfree,             // 21

    time::gettimeofday,     // 22

    video::control,         // 23
    video::release,         // 24

    dir::getdirents,        // 25

    rand::fillrandom,       // 26

    audio::open,            // 27
    audio::manage,          // 28
    audio::write,           // 29
    audio::read,            // 30
    audio::close,           // 31

    thread::create,         // 32
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

    qemu_log!("System call: {nr}");

    if let Some(handler) = SYSCALL_HANDLERS.get(nr) {
        let result = handler(arg1, arg2, arg3, arg4, arg5);

        // If the call was successful, the result is being returned
        // If error was encountered, the error code is being translated into u32
        // (see noct_io::error::Error, it's the enum's underlying type) then into isize,
        // gets negated and then casted into usize.
        let raw_result = match result {
            Ok(val) => val,
            Err(e) => (-((e as u32) as isize)) as usize
        };

        #[cfg(target_arch = "x86")]
        {
            regs.eax = raw_result as u32;
        }
        #[cfg(target_arch = "x86_64")]
        {
            regs.rax = raw_result as u64;
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
