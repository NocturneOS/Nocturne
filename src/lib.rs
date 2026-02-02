#![no_std]

use core::{panic::PanicInfo, time::Duration};

use crate::{
    sched::thread::ThreadFlags,
};

mod arch;
mod interrupts;
mod io;
mod mem;
mod sched;
mod spec;
mod sys;
mod time;
mod tools;
mod unwind;

extern crate alloc;

fn test_task() {
    loop {
        qemu_log!("Hello, world!");

        sched::sleep(Duration::from_secs(1));
    }
}

// This entry point is called from `arch_init`.
extern "C" fn kmain() -> ! {
    // Now `__arch_init` initialized paging and PMM for us.
    // To make kernel fully initialized we should initialize heap.

    mem::heap::init();

    sched::init();

    {
        for _ in 0..128 {
            sched::create_thread(
                test_task,
                0x1000,
                ThreadFlags::empty(),
            );
            
            sched::sleep(Duration::from_millis(50));
        }

        loop {
            qemu_println!("Main!");

            sched::sleep(Duration::from_millis(500));
        }
    }

    // clear_screen();
    // test_write();

    qemu_log!("It works!");

    loop {
        arch::halt();
    }
}

#[panic_handler]
fn __panic_handler(info: &PanicInfo) -> ! {
    if let Some(loc) = info.location() {
        qemu_log!(
            "Kernel panicked at {}:{}:{}: {:#?}",
            loc.file(),
            loc.line(),
            loc.column(),
            info.message()
        );
    } else {
        qemu_log!("Kernel panicked: {:?}", info.message());
    }

    unsafe { unwind::backtrace() };

    arch::halt_forever()
}
