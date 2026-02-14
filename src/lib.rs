#![no_std]

use core::{panic::PanicInfo, time::Duration};

use alloc::{collections::{btree_map::BTreeMap, linked_list::LinkedList, vec_deque::VecDeque}, string::String};

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
    // let mut inner_counter = 0;

    loop {
        let id = sched::this_thread_id();

        qemu_println!("Hello, my ID is: {id:?}");

        sched::sleep(Duration::from_millis(id as u64 * 5));

        // if inner_counter > 5 {
        qemu_println!("Exiting: {id:?}");
        break;
        // }
        
        // inner_counter += 1;
    }
}

// This entry point is called from `arch_init`.
extern "C" fn kmain() -> ! {
    // Now `__arch_init` initialized paging and PMM for us.
    // To make kernel fully initialized we should initialize heap.

    mem::heap::init();

    // {
    //     let mut list = VecDeque::new();

    //     for i in 0..490 {
    //         list.push_back(i);
    //     }
        
    //     let mut bm = BTreeMap::new();

    //     bm.insert("abc", String::from("def"));
    //     bm.insert("123", String::from("456"));
    //     bm.insert("???", String::from("!!!"));
    //     bm.insert("101", String::from("666"));

    //     qemu_println!("{bm:?}");

    //     for i in &list {
    //         qemu_print!("{i}, ");
    //     }
        
    //     qemu_println!();

    //     qemu_log!("OK!");

    //     // mem::heap::dump();

    //     loop {}
    // }
    
    sched::init();
    
    {
        for _ in 0..128 {
            sched::create_thread(
                test_task,
                sched::KERNEL_THREAD_DEFAULT_STACK_SIZE,
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
