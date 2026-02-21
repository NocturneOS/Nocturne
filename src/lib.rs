#![no_std]
#![feature(linked_list_retain)]

use core::{panic::PanicInfo, time::Duration};

use alloc::{collections::{btree_map::BTreeMap, linked_list::LinkedList, vec_deque::VecDeque}, format, string::String, vec::Vec};

use crate::sched::thread::{ThreadFlags, ThreadPriority::{self, Medium}};

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
    let id = sched::this_thread_id();
    let mut counter: usize = 0;

    loop {
        qemu_println!("Hello, my ID is: {id:?}");

        // sched::sleep(Duration::from_millis(2));

        counter = counter.wrapping_add(1);

        if counter == 0xff {
            qemu_println!("Exiting: {id:?}");
            break;
        }
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
                sched::KERNEL_THREAD_DEFAULT_STACK_SIZE,
                ThreadPriority::Low,
                ThreadFlags::empty(),
            );
        }

        loop {
            qemu_log!("Main thread!");

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
