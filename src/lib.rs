#![no_std]

use core::panic::PanicInfo;

use alloc::{borrow::ToOwned, boxed::Box};
use noct_boot::{BootInfo, Module};
use noct_logger::qemu_log;
use noct_mem::{heap, paging::PageFlags};
use noct_memdisk::MemoryDisk;

use crate::arch::x86::multiboot::MultibootModule;

mod arch;
mod syscalls;
mod time;
mod unwind;

extern crate alloc;

// This entry point is called from `arch_init`.
fn kmain(boot_info: &dyn BootInfo<ModuleType = MultibootModule>) -> ! {
    // Now `__arch_init` initialized paging and PMM for us.
    // To make kernel fully initialized we should initialize heap.

    heap::init();

    noct_sched::init();

    // {
    //     qemu_log!("Creating 32 processes...");

    //     let procs: [_; 32] = core::array::from_fn(|_| noct_sched::create_process("proc", "?"));

    //     qemu_log!("32 processes have been created!");

    //     core::mem::drop(procs);

    //     let proc = noct_sched::this_process();

    //     for _ in 0..32 {
    //         noct_sched::create_thread(
    //             Arc::clone(&proc),
    //             move || {
    //                 let id = noct_sched::this_thread_id();

    //                 loop {
    //                     qemu_log!("Hi thread #{}", id);
    //                     noct_sched::sleep(Duration::from_millis((id * 40) as _));
    //                 }
    //             },
    //             noct_sched::KERNEL_THREAD_DEFAULT_STACK_SIZE,
    //             noct_sched::thread::ThreadPriority::Low,
    //             noct_sched::thread::ThreadFlags::empty(),
    //         );
    //     }
    // }

    // loop {}

    noct_pci::scan();

    for i in noct_pci::devices().iter() {
        qemu_log!(
            "[{}.{}.{}]: ({}:{}): {:04x}:{:04x}",
            i.bus,
            i.slot,
            i.function,
            i.class,
            i.subclass,
            i.vendor,
            i.device
        );
    }

    {
        noct_mem::paging::map_pages(0xf_0000, 0xf_0000, 0x1_0000, PageFlags::Present);

        if let Some(smbios) = noct_smbios::find_smbios() {
            let values = smbios.scan();

            for i in values {
                qemu_log!("{i:#?}");
            }
        }

        noct_mem::paging::unmap_pages(0xf_0000, 0x1_0000);
    }

    noct_ps2::init();

    // clear_screen();
    // test_write();

    crate::arch::x86::dev::ata::init();

    for (idx, disk) in noct_diskman::disk_list().iter().enumerate() {
        qemu_log!(
            "#{}: id={}, name={}, type={:?}, capacity={} blocks {} bytes each, is_partition={}",
            idx,
            disk.id,
            disk.name,
            disk.drive_type,
            disk.capacity.unwrap(),
            disk.block_size.unwrap(),
            disk.is_partition
        );
    }

    // noct_fsman::store::register_filesystem(Box::new(noct_fsman::nullfs::NullFilesystem));
    noct_fsman::store::register_filesystem(Box::new(noct_iso9660::ISO9660Filesystem));
    noct_fsman::store::register_filesystem(Box::new(noct_tarfs::TarFilesystem));
    // noct_fsman::store::register_filesystem(Box::new(noct_fsman::debugfs::DebugFilesystem));

    for i in boot_info.modules() {
        if i.cmdline().map(|x| x == "ramdisk").unwrap_or(false) {
            qemu_log!(
                "Would make disk from module: {:X} - {:X} ({:?})",
                i.start(),
                i.end(),
                i.cmdline()
            );

            noct_diskman::register_drive(Box::new(MemoryDisk::raw_physical(i.start(), i.size())))
                .ok();
        }
    }

    noct_fsman::probe();

    syscalls::init();

    {
        let (handle, tid) = noct_elfloader::spawn("mem0:/prog").unwrap();

        qemu_log!("Started process {}", handle.id);
        qemu_log!("Thread ID {}", tid);
        // handle.unwrap().run(&[]);
    }

    qemu_log!("It works!");

    loop {
        arch::halt();
    }
}

#[panic_handler]
fn __panic_handler(info: &PanicInfo) -> ! {
    noct_interrupts::cpu::disable_interrupts();

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
