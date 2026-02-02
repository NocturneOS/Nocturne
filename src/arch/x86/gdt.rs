use spin::mutex::Mutex;

const ACCESS_PRESENT: u8 = 1 << 7;
const ACCESS_DPL_0: u8 = 0 << 5;
const ACCESS_DPL_3: u8 = 3 << 5;
const ACCESS_CODE_OR_DATA: u8 = 1 << 4;
const ACCESS_EXECUTABLE: u8 = 1 << 3;
const ACCESS_DIRECTION_CONFORMING: u8 = 1 << 2;
const ACCESS_RW: u8 = 1 << 1;
const ACCESS_ACCESSED: u8 = 1 << 0;

#[repr(C, packed(1))]
struct GDTEntry {
    limit_low: u16,
    base_low: u16,
    base_middle: u8,
    access: u8,
    granularity: u8,
    base_high: u8,
    #[cfg(target_arch = "x86_64")]
    base_higher: u32,
    #[cfg(target_arch = "x86_64")]
    reserved: u32
}

impl GDTEntry {
    pub fn new(base: usize, limit: u32, access: u8, flags: u8) -> Self {
        Self {
            base_low: (base & 0xffff) as u16,
            base_middle: ((base >> 16) & 0xff) as u8,
            base_high: ((base >> 24) & 0xff) as u8,
            limit_low: (limit & 0xffff) as u16,
            granularity: (((limit >> 16) & 0xf) as u8 | (flags << 4)),
            access,
            #[cfg(target_arch = "x86_64")]
            base_higher: (base >> 32) as u32,
            #[cfg(target_arch = "x86_64")]
            reserved: 0
        }
    }
}

static GDT_ENTRIES: Mutex<[GDTEntry; 6]> = unsafe { core::mem::zeroed() };

unsafe extern "C" {
    fn gdt_flush(gdt_ptr: &x86::dtables::DescriptorTablePointer<GDTEntry>);
}

#[rustfmt::skip]
pub fn init() {
    let mut binding = unsafe { GDT_ENTRIES.lock() };

    binding[0] = unsafe { core::mem::zeroed() };

    // 0x08: Ring 0 / Code
    binding[1] = GDTEntry::new(0, 0xffff_ffff, ACCESS_PRESENT | ACCESS_DPL_0 | ACCESS_CODE_OR_DATA | ACCESS_EXECUTABLE | ACCESS_RW, 0b1100);
    
    // 0x10: Ring 0 / Data
    binding[2] = GDTEntry::new(0, 0xffff_ffff, ACCESS_PRESENT | ACCESS_DPL_0 | ACCESS_CODE_OR_DATA | ACCESS_RW, 0b1100);
    
    // 0x18: Ring 3 / Code
    binding[3] = GDTEntry::new(0, 0xffff_ffff, ACCESS_PRESENT | ACCESS_DPL_3 | ACCESS_CODE_OR_DATA | ACCESS_EXECUTABLE | ACCESS_RW , 0b1100);
    
    // 0x20: Ring 3 / Data
    binding[4] = GDTEntry::new(0, 0xffff_ffff, ACCESS_PRESENT | ACCESS_DPL_3 | ACCESS_CODE_OR_DATA | ACCESS_RW, 0b1100);

    let entries = binding;

    unsafe {
        gdt_flush(&x86::dtables::DescriptorTablePointer {
            limit: (core::mem::size_of::<GDTEntry>() * entries.len() - 1) as u16,
            base: entries.as_ptr()
        });
    };
}
