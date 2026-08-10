#![no_std]

use core::panic::PanicInfo;

use alloc::boxed::Box;
use noct_boot::{BootInfo, Module};
use noct_logger::qemu_log;
use noct_mem::{heap, paging::PageFlags};
use noct_memdisk::MemoryDisk;
use noct_multiboot::MultibootModule;
use noct_tty::tty_println;

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

    crate::arch::post_init(boot_info);

    // noct_input::init();

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

    {
        let (rows, cols) = {
            let bind = noct_video::CURRENT_VIDEO_MODE.lock();
            let display_size = bind.as_ref().unwrap().resolution();

            (display_size.height / 8, display_size.width / 16)
        };

        // noct_tty::init(25, 80);
        noct_tty::init(rows, cols);

        tty_println!("\x1b[33mNocturneOS {}", env!("CARGO_PKG_VERSION"));
    }

    syscalls::init();

    {
        let handle = noct_elfloader::spawn("mem0:/prog_stdin", &[]).unwrap();

        qemu_log!("Started process {}", handle.pid);

        let code = handle.wait();

        qemu_log!("Process exited with code: {code:?}");
    }

    {
        let (data, time) = noct_tools::measure_time_timer(|| noct_fs::read_file("ata0:/hello.txt"));

        qemu_log!("Time: {} ms", time);

        match data {
            Ok(data) => {
                let s = str::from_utf8(&data).unwrap();

                qemu_log!("Data: {s:?}");
            }
            Err(e) => {
                qemu_log!("Error: {e:?}");
            }
        }
    }

    // {
    //     let mut lock = noct_video::CURRENT_VIDEO_MODE.lock();

    //     let mut canvas = noct_video::canvas::Canvas::new(lock.as_mut().unwrap());

    //     canvas.fill(0x00_00_00_ff << 16);   // AA_RR_GG_BB
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
