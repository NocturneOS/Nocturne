use core::{arch::asm};

use spin::Mutex;

use crate::{arch, qemu_log};

static IS_BACKTRACING: Mutex<bool> = Mutex::new(false);

#[repr(C, packed)]
pub struct Frame {
    fp: *const usize, // Frame pointer
    lr: *const usize, // Return address
}

pub unsafe extern "C" fn backtrace() {
    if *IS_BACKTRACING.lock() {
        qemu_log!("Recursive backtracing is stopped.");

        arch::halt_forever();
    }

    *IS_BACKTRACING.lock() = true;

    let mut frame: *const Frame;

    #[cfg(target_arch = "x86")]
    unsafe {
        asm!("mov {}, ebp", out(reg) frame)
    };

    #[cfg(target_arch = "x86_64")]
    asm!("mov {}, rbp", out(reg) frame);

    while !frame.is_null() {
        let f = unsafe { &*frame };
        let return_addr = f.lr.addr();

        if return_addr == 0 {
            break;
        }

        qemu_log!("-  <unknown> ({:#x})", return_addr);

        frame = f.fp as *const _;
    }
}
