#![no_std]

use core::ffi::{CStr, c_char};

use noct_boot::{BootVideoInfo, MemoryInfo, ModuleIterator};
use noct_spec::KERNEL_BASE;

#[repr(C, packed)]
#[derive(Debug)]
pub struct MultibootHeader {
    pub flags: u32,
    pub mem_lower: u32,
    pub mem_upper: u32,
    pub boot_device: u32,
    pub cmdline: u32,
    pub mods_count: u32,
    pub mods_addr: u32,
    pub num: u32,
    pub size: u32,
    pub addr: u32,
    pub shndx: u32,
    pub mmap_length: u32,
    pub mmap_addr: u32,
    pub drives_length: u32,
    pub drives_addr: u32,
    pub config_table: u32,
    pub boot_loader_name: u32,
    pub apm_table: u32,
    pub vbe_control_info: u32,
    pub vbe_mode_info: u32,
    pub vbe_mode: u16,
    pub vbe_interface_seg: u16,
    pub vbe_interface_off: u16,
    pub vbe_interface_len: u16,
    pub framebuffer_addr: u64,
    pub framebuffer_pitch: u32,
    pub framebuffer_width: u32,
    pub framebuffer_height: u32,
    pub framebuffer_bpp: u8,
    pub framebuffer_type: u8,
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct MultibootMMapEntry {
    pub size: u32,
    pub addr_low: u32,
    pub addr_high: u32,
    pub len_low: u32,
    pub len_high: u32,
    pub type_: u32,
}

#[derive(Debug, PartialEq)]
pub enum MultibootMMapType {
    Available,
    ACPI,
    Reserved,
    NVS,
    BadRAM,
}

#[repr(C, packed(1))]
#[derive(Debug, Copy, Clone)]
pub struct MultibootModule {
    pub mod_start: u32,
    pub mod_end: u32,
    pub cmdline: u32,
    pub reserved: u32,
}

impl MultibootHeader {
    pub fn mmap(&self) -> &[MultibootMMapEntry] {
        unsafe {
            core::slice::from_raw_parts(
                (self.mmap_addr as usize + KERNEL_BASE) as _,
                (self.mmap_length as usize / core::mem::size_of::<MultibootMMapEntry>()) as _,
            )
        }
    }
}

impl MultibootMMapEntry {
    pub fn addr(&self) -> u64 {
        (self.addr_high as u64) << 32 | self.addr_low as u64
    }

    pub fn length(&self) -> u64 {
        (self.len_high as u64) << 32 | self.len_low as u64
    }

    pub fn ty(&self) -> MultibootMMapType {
        let ty = self.type_;

        match ty {
            1 => MultibootMMapType::Available,
            2 => MultibootMMapType::Reserved,
            3 => MultibootMMapType::ACPI,
            4 => MultibootMMapType::NVS,
            5 => MultibootMMapType::BadRAM,
            _ => todo!("Invalid MMAP type: 0x{:x}", ty),
        }
    }
}

impl noct_boot::BootInfo for MultibootHeader {
    type ModuleType = MultibootModule;

    fn memory(&self) -> noct_boot::MemoryInfo {
        MemoryInfo::new((self.mem_lower << 10) as _, (self.mem_upper << 10) as _)
    }

    fn cmdline(&self) -> &str {
        unsafe {
            CStr::from_ptr((self.cmdline as usize + KERNEL_BASE) as *const c_char)
                .to_str()
                .unwrap()
        }
    }

    fn modules(&self) -> noct_boot::ModuleIterator<Self::ModuleType> {
        ModuleIterator::new(
            (self.mods_addr as usize + KERNEL_BASE) as _,
            self.mods_count as _,
        )
    }

    fn video(&self) -> noct_boot::BootVideoInfo {
        BootVideoInfo {
            fb_addr: self.framebuffer_addr,
            fb_pitch: self.framebuffer_pitch,
            fb_width: self.framebuffer_width,
            fb_height: self.framebuffer_height,
            fb_bpp: self.framebuffer_bpp,
            fb_type: self.framebuffer_type,
        }
    }
}

impl noct_boot::Module for MultibootModule {
    fn cmdline(&self) -> Option<&str> {
        unsafe {
            let cstr = CStr::from_ptr((self.cmdline as usize + KERNEL_BASE) as *const c_char);

            cstr.to_str().ok()
        }
    }

    fn start(&self) -> usize {
        self.mod_start as _
    }

    fn end(&self) -> usize {
        self.mod_end as _
    }
}
