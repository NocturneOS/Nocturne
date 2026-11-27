use noct_mem::paging::PageFlags;

pub struct Lapic {
    base: usize,

    mem_handle: noct_mem::paging::MappingContext,
}

impl Lapic {
    pub fn init() -> Self {
        let lapic_base = unsafe { x86::msr::rdmsr(x86::msr::APIC_BASE) } & 0xffff_f000;

        // Enable APIC (bit 11), set the bootstrap processor (bit 8).
        unsafe { x86::msr::wrmsr(x86::msr::APIC_BASE, lapic_base | (1 << 8) | (1 << 11)) };

        let hdl = noct_mem::paging::MappingContext::map(
            lapic_base as _,
            lapic_base as _,
            4096,
            PageFlags::Writeable,
        );

        Lapic {
            base: lapic_base as _,
            mem_handle: hdl,
        }
    }

    #[inline]
    pub fn write(&self, reg: u32, value: u32) {
        unsafe { ((self.base + reg as usize) as *mut u32).write_volatile(value) };
    }

    #[inline]
    pub fn read(&self, reg: u32) -> u32 {
        unsafe { ((self.base + reg as usize) as *mut u32).read_volatile() }
    }
}
