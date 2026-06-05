use lazy_static::lazy_static;

pub const ACCESS_PRESENT: u8 = 1 << 7;
pub const ACCESS_DPL_0: u8 = 0 << 5;
pub const ACCESS_DPL_3: u8 = 3 << 5;
pub const ACCESS_CODE_OR_DATA: u8 = 1 << 4;
pub const ACCESS_EXECUTABLE: u8 = 1 << 3;
pub const ACCESS_DIRECTION_CONFORMING: u8 = 1 << 2;
pub const ACCESS_RW: u8 = 1 << 1;
pub const ACCESS_ACCESSED: u8 = 1 << 0;

pub const FLAG_GRANULARITY: u8 = 1 << 3;
pub const FLAG_SIZE: u8 = 1 << 2;
pub const FLAG_LONGMODE: u8 = 1 << 1;

#[repr(C, packed(1))]
pub struct GDTEntry {
    limit_low: u16,
    base_low: u16,
    base_middle: u8,
    access: u8,
    granularity: u8,
    base_high: u8,
}

impl GDTEntry {
    pub fn new(base: u32, limit: u32, access: u8, flags: u8) -> Self {
        Self {
            base_low: (base & 0xffff) as u16,
            base_middle: ((base >> 16) & 0xff) as u8,
            base_high: ((base >> 24) & 0xff) as u8,
            limit_low: (limit & 0xffff) as u16,
            granularity: (((limit >> 16) & 0xf) as u8 | (flags << 4)),
            access,
        }
    }
}

#[repr(align(16))]
pub struct GDT<const N: usize> {
    entries: [GDTEntry; N],
}

impl<const N: usize> GDT<N> {
    #[allow(clippy::mut_from_ref)]
    pub fn nth(&self, index: usize) -> &mut GDTEntry {
        if index >= N {
            panic!("GDT out of range");
        }

        unsafe { &mut *(self.entries.as_ptr() as *mut GDTEntry).add(index) }
    }

    pub fn nth_ptr(&self, index: usize) -> *mut GDTEntry {
        if index >= N {
            panic!("GDT out of range");
        }

        unsafe { (self.entries.as_ptr() as *mut GDTEntry).add(index) }
    }

    pub fn len(&self) -> usize {
        N
    }
}

unsafe impl<const N: usize> Sync for GDT<N> {}
unsafe impl<const N: usize> Send for GDT<N> {}

lazy_static! {
    pub static ref GDT_ENTRIES: GDT<7> = unsafe { core::mem::zeroed() };
}

unsafe extern "C" {
    fn gdt_flush(gdt_ptr: &x86::dtables::DescriptorTablePointer<GDTEntry>);
}

#[rustfmt::skip]
pub fn init() {
	let code_flags: u8 = {
		#[cfg(target_arch = "x86")]
      { FLAG_GRANULARITY | FLAG_SIZE }
		#[cfg(target_arch = "x86_64")]
      { FLAG_GRANULARITY | FLAG_LONGMODE }
	};

	let data_flags = FLAG_GRANULARITY | FLAG_SIZE;

    *GDT_ENTRIES.nth(0) = unsafe { core::mem::zeroed() };

    // 0x08: Ring 0 / Code
    *GDT_ENTRIES.nth(1) = GDTEntry::new(0, 0xffff_ffff, ACCESS_PRESENT | ACCESS_DPL_0 | ACCESS_CODE_OR_DATA | ACCESS_EXECUTABLE | ACCESS_RW, code_flags);
    
    // 0x10: Ring 0 / Data
    *GDT_ENTRIES.nth(2) = GDTEntry::new(0, 0xffff_ffff, ACCESS_PRESENT | ACCESS_DPL_0 | ACCESS_CODE_OR_DATA | ACCESS_RW, data_flags);
    
    // 0x18: Ring 3 / Code
    *GDT_ENTRIES.nth(3) = GDTEntry::new(0, 0xffff_ffff, ACCESS_PRESENT | ACCESS_DPL_3 | ACCESS_CODE_OR_DATA | ACCESS_EXECUTABLE | ACCESS_RW , code_flags);
    
    // 0x20: Ring 3 / Data
    *GDT_ENTRIES.nth(4) = GDTEntry::new(0, 0xffff_ffff, ACCESS_PRESENT | ACCESS_DPL_3 | ACCESS_CODE_OR_DATA | ACCESS_RW, data_flags);

    let entries = &GDT_ENTRIES.entries;

    unsafe {
        gdt_flush(&x86::dtables::DescriptorTablePointer {
            limit: (core::mem::size_of::<GDTEntry>() * entries.len() - 1).try_into().expect("Failed to convert limit to u16"),
            base: entries.as_ptr()
        });
    };
}
