#![no_std]

use core::panic::PanicInfo;

use alloc::boxed::Box;
use noct_boot::{BootInfo, Module};
use noct_logger::qemu_log;
use noct_mem::{heap, paging::PageFlags};
use noct_memdisk::MemoryDisk;
use noct_multiboot::MultibootModule;
use noct_sched::thread::ThreadFlags;

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

    crate::arch::post_init();

    noct_sched::init();

    // {
    //     qemu_log!("Creating 32 processes...");

    //     let procs: [_; 32] = core::array::from_fn(|_| noct_sched::create_process("proc", "?"));

    //     qemu_log!("32 processes have been created!");

    //     core::mem::drop(procs);

    //     let proc = noct_sched::this_process();

    //     for _ in 0..32 {
    //         noct_sched::create_thread(
    //             alloc::sync::Arc::clone(&proc),
    //             move || {
    //                 let id = noct_sched::this_thread_id();

    //                 loop {
    //                     qemu_log!("Hi thread #{}", id);
    //                     noct_sched::sleep(core::time::Duration::from_millis((id * 40) as _));
    //                 }
    //             },
    //             noct_sched::KERNEL_THREAD_DEFAULT_STACK_SIZE,
    //             noct_sched::thread::ThreadPriority::Low,
    //             noct_sched::thread::ThreadFlags::empty(),
    //             &[]
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

            qemu_log!(
                "Result: {:?}",
                noct_diskman::register_drive(Box::new(MemoryDisk::raw_physical(
                    i.start(),
                    i.size()
                )))
            );
        }
    }

    noct_fsman::probe();

    syscalls::init();

    {
        let handle = noct_elfloader::spawn("mem0:/prog2_64", &["abc", "def"]).unwrap();

        qemu_log!("Started process {}", handle.pid);

        let code = handle.wait();

        qemu_log!("Process exited with code: {code:?}");

        // let il = noct_tools::interrupt_locker::InterruptLocker::lock();

        // let proc = noct_sched::create_process_inherit("test process");

        // // Allocate a page, map it into the new process at 0x400000, and write some code there that just loops forever.
        // let phys = unsafe {
        //     proc.address_space
        //         .get_mut()
        //         .alloc_map_single_page(0x40_0000, PageFlags::Writeable | PageFlags::Userspace)
        //         .unwrap()
        // };

        // // Context is a RAII guard that will automatically unmap the page when it goes out of scope, so we don't have to worry about cleaning up if something goes wrong.
        // let ctx =
        //     noct_mem::paging::MappingContext::map(phys, 0x100_0000, 0x1000, PageFlags::Writeable);

        // let code: &[u8] = &[0xeb, 0xfe, 0x90];

        // unsafe { (0x100_0000 as *mut u8).copy_from(code.as_ptr(), code.len()) };

        // drop(ctx);

        // // And finally create thread.
        // let thread = noct_sched::create_thread(
        //     proc,
        //     unsafe { core::mem::transmute(0x40_0000 as *const ()) },
        //     0x1000,
        //     noct_sched::thread::ThreadPriority::Low,
        //     ThreadFlags::User,  // TODO: Not actually needed, because any PID > 0 is userspace, remove that flag from the scheduler.
        //     &[],
        // );

        // qemu_log!("Created thread: {thread:?}");

        // drop(il);
    }

    // {
    //     let (data, time) = noct_tools::measure_time_timer(|| noct_fs::read_file("ata0:/hello.txt"));

    //     qemu_log!("Time: {} ms", time);

    //     match data {
    //         Ok(data) => {
    //             let s = str::from_utf8(&data).unwrap();

    //             qemu_log!("Data: {s:?}");
    //         },
    //         Err(e) => {
    //             qemu_log!("Error: {e:?}");
    //         },
    //     }
    // }

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
