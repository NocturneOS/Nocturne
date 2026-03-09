#![no_std]
#![feature(linked_list_retain)]

use core::{panic::PanicInfo, time::Duration};

use alloc::{collections::{btree_map::BTreeMap, linked_list::LinkedList, vec_deque::VecDeque}, format, string::String, sync::Arc, vec::Vec};

use crate::{arch::mem::address_space_manager::AddressSpace, sched::thread::{ThreadFlags, ThreadPriority::{self, Medium}}, tools::without_interrupts::without_interrupts};

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
        let cr3 = unsafe { x86::controlregs::cr3() };

        qemu_log!("Hello, my ID is: {id:?} (CR3: {cr3:08x?})");

        sched::sleep(Duration::from_millis((10 * id) as _));

        counter = counter.wrapping_add(1);

        if counter == 0x40 {
            qemu_log!("Exiting: {id:?}");
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
        //{
        //    let proc = sched::create_process("Test Process", "rd0:/");

        //    qemu_log!("Process CR3: {:x?}", proc.address_space.get().page_root_phys);
        //    sched::create_thread(Arc::clone(&proc), test_task, 16 << 10, ThreadPriority::Low, ThreadFlags::empty());
        //    sched::create_thread(Arc::clone(&proc), test_task, 16 << 10, ThreadPriority::Low, ThreadFlags::empty());
        //    sched::create_thread(Arc::clone(&proc), test_task, 16 << 10, ThreadPriority::Low, ThreadFlags::empty());
        //    sched::create_thread(Arc::clone(&proc), test_task, 16 << 10, ThreadPriority::Low, ThreadFlags::empty());
        //}

        for _ in 0..16 {
            let proc = sched::create_process("Test Process", "rd0:/");
            
            for _ in 0..16 {
                sched::create_thread(
                    Arc::clone(&proc),
                    test_task,
                    16 << 10,
                    ThreadPriority::Low,
                    ThreadFlags::empty(),
                );
            }
        }

        // for _ in 0..128 {
        //     sched::create_thread(
        //         sched::this_process(),
        //         test_task,
        //         16 << 10,
        //         ThreadPriority::Low,
        //         ThreadFlags::empty(),
        //     );
        // }

        // mem::heap::dump();

        loop {
            let cr3 = unsafe { x86::controlregs::cr3() };
            qemu_log!("Main thread! CR3: {cr3:08x?}");

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
