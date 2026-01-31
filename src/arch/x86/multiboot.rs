use core::ffi::{CStr, c_char};

use crate::spec::KERNEL_BASE;

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

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct MultibootModule {
    pub mod_start: u32,
    pub mod_end: u32,
    pub cmdline: u32,
    pub reserved: u32,
}

pub struct MemorySize {
    low: usize,
    high: usize,
}

impl MemorySize {
    #[inline]
    pub fn low(&self) -> usize {
        self.low << 10
    }

    #[inline]
    pub fn high(&self) -> usize {
        self.high << 10
    }

    #[inline]
    pub fn total(&self) -> usize {
        self.low() + self.high()
    }
}

impl MultibootHeader {
    pub fn memory(&self) -> MemorySize {
        let low = self.mem_lower;
        let high = self.mem_upper;

        MemorySize {
            low: low as _,
            high: high as _,
        }
    }

    pub fn cmdline(&self) -> &str {
        unsafe {
            CStr::from_ptr((self.cmdline as usize + KERNEL_BASE) as *const c_char)
                .to_str()
                .unwrap()
        }
    }

    pub fn modules(&self) -> &[MultibootModule] {
        unsafe {
            core::slice::from_raw_parts(
                (self.mods_addr as usize + KERNEL_BASE) as _,
                self.mods_count as _,
            )
        }
    }

    pub fn mmap(&self) -> &[MultibootMMapEntry] {
        unsafe {
            core::slice::from_raw_parts(
                (self.mmap_addr as usize + KERNEL_BASE) as _,
                (self.mmap_length as usize / core::mem::size_of::<MultibootMMapEntry>()) as _,
            )
        }
    }
}

impl MultibootModule {
    pub fn cmdline(&self) -> &str {
        unsafe {
            let cstr = CStr::from_ptr((self.cmdline as usize + KERNEL_BASE) as *const c_char);

            cstr.to_str().unwrap()
        }
    }

    pub fn start(&self) -> usize {
        let start = self.mod_start;

        start as usize
    }

    pub fn end(&self) -> usize {
        let end = self.mod_end;

        end as usize
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
