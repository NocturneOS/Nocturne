#![no_std]
#![feature(linked_list_retain)]

use core::panic::PanicInfo;

mod arch;
mod interrupts;
mod io;
mod mem;
mod sched;
mod sys;
mod time;
mod tools;
mod unwind;

extern crate alloc;

// This entry point is called from `arch_init`.
extern "C" fn kmain() -> ! {
    // Now `__arch_init` initialized paging and PMM for us.
    // To make kernel fully initialized we should initialize heap.

    mem::heap::init();
    
    sched::init();

    arch::x86::dev::pci::scan();

    for i in arch::x86::dev::pci::devices().iter() {
        qemu_log!("[{}.{}.{}]: ({}:{}): {:04x}:{:04x}", i.bus, i.slot, i.function, i.class, i.subclass, i.vendor, i.device);
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
    arch::disable_interrupts();
    
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
