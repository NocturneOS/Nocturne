#![no_std]

mod load;

use core::ffi::c_char;

use noct_mem::paging::PageFlags;

use alloc::{ffi::CString, string::String, sync::Arc, vec::Vec};
use elf::{ParseError, endian::LittleEndian};
use noct_logger::qemu_log;
use noct_sched::{
    process::Process,
    thread::{ThreadFlags, ThreadPriority},
};
use noct_tools::align_value;

use crate::load::{LoadInfo, LoadedSegments};

extern crate alloc;

#[derive(Debug)]
pub enum LoadError {
    System(noct_io::error::Error),
    InvalidELFType,
    UnsupportedArchitecture,
    ElfParser(ParseError),
    ThreadCreationFail,
}

#[derive(Debug)]
pub struct ProgramHandle {
    path: String,

    entry_point: usize,
    loaded_segments: LoadedSegments,
}

impl ProgramHandle {
    pub fn run(&mut self, args: &[&str]) {
        let mut normalized: Vec<CString> = Vec::with_capacity(1 + args.len());

        normalized.push(CString::new(self.path.clone()).unwrap());
        normalized.extend_from_slice(
            args.iter()
                .map(|a| CString::new(*a).unwrap())
                .collect::<Vec<_>>()
                .as_slice(),
        );

        let mut ptrs = normalized
            .iter()
            .map(|a| a.as_ptr())
            .collect::<Vec<*const c_char>>();
        ptrs.push(core::ptr::null());

        let argc: u32 = (ptrs.len() - 1) as u32;
        let argv = ptrs.as_ptr();

        unsafe {
            let entry: fn(u32, *const *const c_char) = core::mem::transmute(self.entry_point);

            qemu_log!(
                "program < argc: {argc}; argv: {:x?}; entry: {:x?}",
                argv as usize,
                entry as usize
            );

            (entry)(argc, argv);
        }
    }
}

impl Drop for ProgramHandle {
    fn drop(&mut self) {
        qemu_log!("Should drop!");
    }
}

pub fn spawn(path: &str) -> Result<(Arc<Process>, usize), LoadError> {
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

    let mut loaded_segments = LoadedSegments::new();

    for i in segments.iter() {
        qemu_log!("PH: {i:x?}");

        if i.p_type != elf::abi::PT_LOAD {
            continue;
        }

        let ph_data = match elf.segment_data(&i) {
            Ok(data) => data,
            Err(e) => {
                qemu_log!("Error happened during load! ({e})");

                return Err(LoadError::ElfParser(e));
            }
        };

        let page_count = {
            let start_addr = (i.p_vaddr & !0xfff) as usize;
            let end_addr = align_value((i.p_vaddr + i.p_memsz) as _, noct_mem::get_page_size());

            (end_addr - start_addr) / noct_mem::get_page_size()
        };

        unsafe {
            let physical_allocation = proc
                .address_space
                .get_mut()
                .alloc_map_multiple_pages(
                    (i.p_vaddr as usize) & !0xfff,
                    page_count * noct_mem::get_page_size(),
                    PageFlags::Writeable | PageFlags::Userspace,
                )
                .unwrap();

            proc.address_space
                .get_mut()
                .map_pages_pa(
                    &physical_allocation,
                    (i.p_vaddr as usize) & !0xfff,
                    PageFlags::Writeable | PageFlags::Userspace,
                )
                .unwrap();

            {
                proc.address_space
                    .get_mut()
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

            loaded_segments.push(LoadInfo {
                physical_allocation: physical_allocation as _,
                virtual_addr: i.p_vaddr as _,
                page_count,
            });
        }
    }

    let thread_id = noct_sched::create_thread(
        Arc::clone(&proc),
        unsafe { core::mem::transmute(elf.ehdr.e_entry as usize) },
        512 << 10, // Stack size = 512 KB
        ThreadPriority::Medium,
        ThreadFlags::User,
        &[0 /* argc */, 0 /* argv */],
    )
    .ok_or(LoadError::ThreadCreationFail)?;

    ////////

    // I put it here for semantics, it doesn't make sense.
    drop(il);

    Ok((proc, thread_id))
}
