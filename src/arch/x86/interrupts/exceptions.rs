use crate::{arch::halt_forever, unwind};

use noct_cpu::CPURegisters;
use noct_interrupts::handler::register_interrupt_handler;
use noct_io::error::{Error, ToPrimitive};
use noct_logger::qemu_println;

fn division_by_zero(regs: &mut CPURegisters) {
    qemu_println!("Division by zero...");

    common_fault_entry(regs);
}

fn general_protection_fault(regs: &mut CPURegisters) {
    qemu_println!("General protection fault...");

    common_fault_entry(regs);
}

fn page_fault(regs: &mut CPURegisters) {
    qemu_println!("Page fault... ({:08x})", unsafe { x86::controlregs::cr2() });

    let err = regs.err_code;

    if (err & 0x1) == 0 {
        qemu_println!("- Not present");
    }

    if (err & 0x2) != 0 {
        qemu_println!("- Read only");
    }

    if (err & 0x4) != 0 {
        qemu_println!("- Not available for user");
    }

    if (err & 0x8) != 0 {
        qemu_println!("- Writing to reserved bits");
    }

    if (err & 0x10) != 0 {
        qemu_println!("- Instruction fetch");
    }

    common_fault_entry(regs);
}

fn sse_fault(regs: &mut CPURegisters) {
    qemu_println!("SSE fault...");

    common_fault_entry(regs);
}

fn common_fault_entry(regs: &mut CPURegisters) {
    // if let Some(id) = crate::sched::this_thread_id() {
    //     qemu_println!("Fault on TID: {}", id);
    // } else {
    //     qemu_println!("Scheduler was disabled (or not initialized)");
    // }

    let pid = noct_sched::this_process().id;
    let tid = noct_sched::this_thread_id();

    qemu_println!("Fault on PID/TID: {pid}/{tid}");

    qemu_println!("{:x?}", regs);

    let sp = {
        #[cfg(target_arch = "x86")]
        {
            regs.esp
        }
        #[cfg(target_arch = "x86_64")]
        {
            regs.rsp
        }
    };

    if sp != 0 {
        #[cfg(target_arch = "x86")]
        unsafe {
            unwind::backtrace_extern(regs.ebp as _)
        };
        #[cfg(target_arch = "x86_64")]
        unsafe {
            unwind::backtrace_extern(regs.rbp as _)
        };
    } else {
        qemu_println!("Stack pointer is NULL. Cannot unwind. Check the scheduler.");
    }

    if pid > 0 {
        // Kill the whole process with code -EMEMORY
        noct_sched::process_exit(Error::MemoryError.to_u32().unwrap().wrapping_neg());
    }

    halt_forever();
}

pub fn register_exceptions() {
    register_interrupt_handler(0, division_by_zero);
    register_interrupt_handler(13, general_protection_fault);
    register_interrupt_handler(14, page_fault);
    register_interrupt_handler(19, sse_fault);
}
