#![no_std]

use noct_elf::load::{LoadInfo, LoadedSegments};
use noct_mem::paging::PageFlags;

use alloc::{string::String, sync::Arc, vec::Vec, vec};
use elf::{ParseError, endian::LittleEndian};
use noct_logger::qemu_log;
use noct_sched::{
    process::{Process, ProcessHandle},
    thread::{ThreadFlags, ThreadPriority},
};
use noct_tools::align_value;

extern crate alloc;

#[derive(Debug)]
pub enum LoadError {
    System(noct_io::error::Error),
    InvalidELFType,
    UnsupportedArchitecture,
    ElfParser(ParseError),
    ThreadCreationFail,
}

pub fn spawn(path: &str, _args: &[&str]) -> Result<Arc<ProcessHandle>, LoadError> {
    // Load data before turning of interrupts.
    let data = match noct_fs::read_file(path) {
        Ok(data) => data,
        Err(e) => {
            qemu_log!("Error: {e:?}");
            return Err(LoadError::System(e));
        }
    };

    let elf = match elf::ElfBytes::<LittleEndian>::minimal_parse(&data) {
        Ok(elf) => elf,
        Err(err) => {
            qemu_log!("parser error: {err}");
            return Err(LoadError::ElfParser(err));
        }
    };

    // 32-bit system allows executing only 32-bit binaries.
    // TODO: Add backward-compatibility support.
    #[cfg(target_arch = "x86")]
    {
        use elf::file::Class;

        if elf.ehdr.class != Class::ELF32 {
            return Err(LoadError::UnsupportedArchitecture);
        }
    }

    // x86-family system allows executing x86 binaries.
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        if !matches!(
            elf.ehdr.e_machine,
            elf::abi::EM_X86_64 | elf::abi::EM_386 | elf::abi::EM_IA_64
        ) {
            return Err(LoadError::UnsupportedArchitecture);
        }
    }

    // Turn interrupts off.
    let il = noct_tools::interrupt_locker::InterruptLocker::lock();

    let proc = noct_sched::create_process_inherit(path);

    //////

    let segments = elf.segments().unwrap();

    for i in segments.iter() {
        qemu_log!("PH: {i:x?}");

        if i.p_type != elf::abi::PT_LOAD {
            continue;
        }

        let ph_data = match elf.segment_data(&i) {
            Ok(data) => data,
            Err(e) => {
                qemu_log!("Error happened during load! ({e})");

                noct_sched::discard_process_entry(proc.id);

                return Err(LoadError::ElfParser(e));
            }
        };

        let page_count = {
            let start_addr = (i.p_vaddr & !0xfff) as usize;
            let end_addr = align_value((i.p_vaddr + i.p_memsz) as _, noct_mem::get_page_size());

            (end_addr - start_addr) / noct_mem::get_page_size()
        };

        unsafe {
            let mut addrspace = proc.address_space.pseudo_lock();

            let physical_allocation = addrspace
                .alloc_map_multiple_pages(
                    (i.p_vaddr as usize) & !0xfff,
                    page_count * noct_mem::get_page_size(),
                    PageFlags::Writeable | PageFlags::Userspace,
                )
                .unwrap();

            addrspace
                .map_pages_pa(
                    &physical_allocation,
                    (i.p_vaddr as usize) & !0xfff,
                    PageFlags::Writeable | PageFlags::Userspace,
                )
                .unwrap();

            {
                addrspace
                    .self_map_data(&physical_allocation, |area| {
                        qemu_log!(
                            "[{physical_allocation:x?}] Zeroing: {:?} (then {} bytes will be copied)",
                            area.as_ptr_range(),
                            ph_data.len()
                        );

                        // Zero out whole area to avoid user programs access some garbage and kernel data.
                        area.fill(0);

                        // `i.p_vaddr` has unaligned addresses sometimes.
                        // `area` is a page-aligned and page-multiple sized slice, so
                        // we should take offset into account.
                        let offset = (i.p_vaddr as usize) & 0xfff;

                        area[offset..][..ph_data.len()].copy_from_slice(ph_data);
                    });
            }

            drop(addrspace);

            proc.program_image
                .as_ref()
                .unwrap()
                .pseudo_lock()
                .loaded_segments
                .push(LoadInfo {
                    physical_allocation: physical_allocation as _,
                    virtual_addr: i.p_vaddr as _,
                    page_count,
                });
        }
    }

    proc.recalculate_heap();

    qemu_log!("Args: {path:?} + {_args:?}");

    let all_args_count = 1 + _args.len(); // +1 for the program name

    let raw_args_size = core::iter::once(path)
        .chain(_args.iter().copied())
        .map(|x| x.len() + 1)
        .sum::<usize>()
        .next_multiple_of(size_of::<usize>());

    // The argument pointers plus the NULL terminator after argv[argc].
    let argv_slots = all_args_count + 1;

    // The total memory size for the arguments, including null terminators.
    let args_memory_size = (raw_args_size
        + argv_slots * core::mem::size_of::<usize>() // For the pointers to the arguments and the NULL terminator
        + core::mem::size_of::<usize>() // For `char** envp`
        + core::mem::size_of::<usize>() // For `char** argv`
        + core::mem::size_of::<usize>()) // For `int argc`
    .next_multiple_of(size_of::<usize>()); // Align the total memory size to the nearest multiple of `usize` for proper alignment.

    // The process entry stack must be 16-byte aligned (SysV/i386 ABI).
    // So pad the beginning (top) of the block, not the end (bottom),
    // so that `argc` still ends up at the final stack pointer.
    let stack_padding = args_memory_size.next_multiple_of(16) - args_memory_size;
    let total_memory_size = args_memory_size + stack_padding;

    let mut values = vec![0_usize; total_memory_size / core::mem::size_of::<usize>()];

    // Now, copy the program name and arguments into the `values` vector
    // Then build up argument list in the format expected by the C runtime (argc, argv)
    // And add pointer to pointer to the arguments list (char** argv) and argument count
    {
        // Skip the zeroed padding at the top of the stack.
        let ptr = unsafe { values.as_mut_ptr().cast::<u8>().add(stack_padding) };

        // Make a vector of bytes that contain raw null-terminated strings.
        let mut raw_args = Vec::with_capacity(raw_args_size);

        for arg in core::iter::once(path).chain(_args.iter().copied()) {
            raw_args.extend_from_slice(arg.as_bytes());
            raw_args.push(0);
        }

        // Write chunks to the top of the stack
        for (idx, i) in raw_args.chunks(size_of::<usize>()).enumerate() {
            let data = unsafe { ptr.add(raw_args_size).sub((idx + 1) * size_of::<usize>()) };

            unsafe {
                data.copy_from(i.as_ptr(), i.len());
            }
        }

        // Args size + 1 terminator.
        let argv_array = unsafe { ptr.add(raw_args_size + size_of::<usize>()).cast::<usize>() };

        // Stack of the first thread of the process is always at 0xC000_0000 or 0x0000_8000_0000_0000 and grows downwards.
        // Account for the padding pushed above the arguments.
        let base = noct_spec::USER_SPACE_TOP - stack_padding;

        // Make argv array
        let mut offset = 0;

        for (i, arg_len) in core::iter::once(path).chain(_args.iter().copied()).map(|x| x.len() + 1).enumerate() {
            unsafe {
                *argv_array.add((all_args_count - i) - 1) = ((base - raw_args_size) + offset) as usize;
            }
            
            offset += arg_len;
        }

        // Terminate argv.
        unsafe {
            *argv_array.sub(1) = 0;
        }

        // Write envp, argv array pointer and argc counter
        let arg_ptr = unsafe { ptr.add(raw_args_size + (argv_slots) * core::mem::size_of::<usize>()).cast::<usize>() };

        unsafe {
            *arg_ptr = 0; // char** envp
            *arg_ptr.add(1) = (base - raw_args_size - argv_slots * core::mem::size_of::<usize>()) as usize; // char** argv
            *arg_ptr.add(2) = all_args_count; // int argc
        }
    }

    // I think it needs some refactoring.

    qemu_log!("Upper stack dump: {values:08x?}");

    let pid = proc.id;

    if noct_sched::create_thread(
        Arc::clone(&proc),
        unsafe { core::mem::transmute(elf.ehdr.e_entry as usize) },
        1024 << 10, // Stack size = 1 MB
        ThreadPriority::Medium,
        ThreadFlags::User,
        &values,
    )
    .is_none()
    {
        // Do not leave a process that will never run in the process table.
        noct_sched::discard_process_entry(pid);

        return Err(LoadError::ThreadCreationFail);
    }

    drop(values);

    ////////

    let hdl = Process::into_handle(proc);

    // I put it here for semantics, it doesn't make sense.
    drop(il);

    Ok(hdl)
}
