#![no_std]

use core::ffi::c_char;

use noct_mem::paging::PageFlags;

use alloc::{ffi::CString, string::String, sync::Arc, vec::Vec};
use elf::{ParseError, endian::LittleEndian};
use noct_logger::qemu_log;
use noct_sched::{process::Process, thread::{ThreadFlags, ThreadPriority}};
use noct_tools::align_value;

extern crate alloc;

#[derive(Debug)]
pub enum LoadError {
    System(noct_io::error::Error),
    InvalidELFType,
    ElfParser(ParseError),
}

#[derive(Debug)]
pub struct LoadInfo {
    physical_addr: usize,
    virtual_addr: usize,
    page_count: usize,
}

#[derive(Debug)]
pub struct ProgramHandle {
    path: String,

    entry_point: usize,
    loaded_segments: Vec<LoadInfo>,
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
        for seg in &self.loaded_segments {
            for page in 0..seg.page_count {
                noct_mem::paging::unmap_single_page(
                    (seg.virtual_addr + (page * noct_mem::paging::PAGE_SIZE as usize)) as _,
                )
            }

            noct_physmem_alloc::free_bulk(seg.physical_addr as _, seg.page_count as _);
        }

        qemu_log!("Should drop!");
    }
}

pub fn spawn(path: &str) -> Result<Arc<Process>, LoadError> {
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

    // Turn interrupts off.
    let il = noct_tools::interrupt_locker::InterruptLocker::lock();

    let proc = noct_sched::create_process_inherit(path);

    //////

    let segments = elf.segments().unwrap();

    let mut loaded_segments: Vec<LoadInfo> = Vec::new();

    for i in segments.iter() {
        if i.p_type != elf::abi::PT_LOAD {
            continue;
        }

        let ph_data = match elf.segment_data(&i) {
            Ok(data) => data,
            Err(e) => {
                qemu_log!("Error happened during load! ({e})");

                // Clean up
                for seg in loaded_segments {
                    unsafe {
                        for page in 0..seg.page_count {
                            proc.address_space.get_mut().unmap_single_page(
                                (seg.virtual_addr + (page * noct_mem::paging::PAGE_SIZE as usize))
                                    as _,
                            )
                        }

                        noct_physmem_alloc::free_bulk(seg.physical_addr as _, seg.page_count as _);
                    }
                }

                return Err(LoadError::ElfParser(e));
            }
        };

        let page_count = {
            let start_addr = (i.p_vaddr & !0xfff) as usize;
            let end_addr = align_value((i.p_vaddr + i.p_memsz) as _, noct_mem::get_page_size());

            // core::cmp::max(
            //     align_value(i.p_memsz as usize, noct_mem::paging::PAGE_SIZE as usize)
            //         / noct_mem::paging::PAGE_SIZE as usize,
            //     1,
            // )

            (end_addr - start_addr) / noct_mem::get_page_size()
        };

        let physical_address = noct_physmem_alloc::allocate_bulk(page_count as _).unwrap();

        unsafe {
            proc.address_space
                .get_mut()
                .map_pages(
                    physical_address,
                    (i.p_vaddr as usize) & !0xfff,
                    (page_count * noct_mem::get_page_size()) as _,
                    PageFlags::Writeable | PageFlags::Userspace,
                )
                .unwrap();

            {
                noct_mem::paging::map_pages(
                    physical_address,
                    (i.p_vaddr as usize) & !0xfff,
                    (page_count * noct_mem::get_page_size()) as _,
                    PageFlags::Writeable | PageFlags::Userspace,
                );

                let memory_area = core::slice::from_raw_parts_mut(
                    i.p_vaddr as *mut u8,
                    (page_count * noct_mem::get_page_size()) - (i.p_vaddr & 0xfff) as usize,
                );

                qemu_log!(
                    "[{physical_address:x?}] Zeroing: {:?}",
                    memory_area.as_ptr_range()
                );

                memory_area[..].fill(0);

                memory_area[..ph_data.len()].copy_from_slice(ph_data);

                noct_mem::paging::unmap_pages(
                    (i.p_vaddr as usize) & !0xfff,
                    (page_count * noct_mem::get_page_size()) as _,
                );
            }
        }

        loaded_segments.push(LoadInfo {
            physical_addr: physical_address as _,
            virtual_addr: i.p_vaddr as _,
            page_count,
        });
    }

    noct_sched::create_thread(
        Arc::clone(&proc),
        unsafe { core::mem::transmute(elf.ehdr.e_entry as usize) },
        512 << 10,  // 512 KB
        ThreadPriority::Medium,
        ThreadFlags::User,
    );

    ////////

    // I put it here for semantics, it doesn't make sense.
    drop(il);

    Ok(proc)
}

pub fn load_elf_file(path: &str) -> Result<ProgramHandle, LoadError> {
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

    let segments = elf.segments().unwrap();

    let mut loaded_segments: Vec<LoadInfo> = Vec::new();

    for i in segments.iter() {
        if i.p_type != elf::abi::PT_LOAD {
            continue;
        }

        let ph_data = match elf.segment_data(&i) {
            Ok(data) => data,
            Err(e) => {
                qemu_log!("Error happened during load! ({e})");

                // Clean up
                for seg in loaded_segments {
                    unsafe {
                        for page in 0..seg.page_count {
                            noct_mem::paging::unmap_single_page(
                                (seg.virtual_addr + (page * noct_mem::paging::PAGE_SIZE as usize))
                                    as _,
                            )
                        }

                        noct_physmem_alloc::free_bulk(seg.physical_addr as _, seg.page_count as _);
                    }
                }

                return Err(LoadError::ElfParser(e));
            }
        };

        let page_count = {
            let start_addr = (i.p_vaddr & !0xfff) as usize;
            let end_addr = align_value((i.p_vaddr + i.p_memsz) as _, noct_mem::get_page_size());

            // core::cmp::max(
            //     align_value(i.p_memsz as usize, noct_mem::paging::PAGE_SIZE as usize)
            //         / noct_mem::paging::PAGE_SIZE as usize,
            //     1,
            // )

            (end_addr - start_addr) / noct_mem::get_page_size()
        };

        let physical_address = noct_physmem_alloc::allocate_bulk(page_count as _).unwrap();

        unsafe {
            noct_mem::paging::map_pages(
                physical_address,
                i.p_vaddr as _,
                (page_count * noct_mem::get_page_size()) as _,
                PageFlags::Writeable | PageFlags::Userspace,
            );

            let memory_area = core::slice::from_raw_parts_mut(
                i.p_vaddr as *mut u8,
                (page_count * noct_mem::get_page_size()) - (i.p_vaddr & 0xfff) as usize,
            );

            qemu_log!(
                "[{physical_address:x?}] Zeroing: {:?}",
                memory_area.as_ptr_range()
            );

            memory_area[..].fill(0);

            memory_area[..ph_data.len()].copy_from_slice(ph_data);
        }

        loaded_segments.push(LoadInfo {
            physical_addr: physical_address as _,
            virtual_addr: i.p_vaddr as _,
            page_count,
        });
    }

    Ok(ProgramHandle {
        path: String::from(path),
        entry_point: elf.ehdr.e_entry as usize,
        loaded_segments,
    })
}
