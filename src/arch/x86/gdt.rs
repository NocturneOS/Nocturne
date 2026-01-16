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
}

impl GDTEntry {
    pub fn new(base: u32, limit: u32, access: u8, flags: u8) -> Self {
        Self {
            base_low: (base & 0xffff) as u16,
            base_middle: ((base >> 16) & 0xff) as u8,
            base_high: ((base >> 24) & 0xff) as u8,
            limit_low: (limit & 0xffff) as u16,
            granularity: (((limit >> 16) & 0xf) as u8 | (flags << 4)) as u8,
            access,
        }
    }
}

static GDT_ENTRIES: spin::Mutex<[GDTEntry; 6]> = unsafe { core::mem::zeroed() };

#[rustfmt::skip]
pub fn init() {
    GDT_ENTRIES.lock()[0] = unsafe { core::mem::zeroed() };

    // 0x08: Ring 0 / Code
    GDT_ENTRIES.lock()[1] = GDTEntry::new(0, 0xffff_ffff, ACCESS_PRESENT | ACCESS_DPL_0 | ACCESS_CODE_OR_DATA | ACCESS_EXECUTABLE | ACCESS_RW, 0b1100);
    
    // 0x10: Ring 0 / Data
    GDT_ENTRIES.lock()[2] = GDTEntry::new(0, 0xffff_ffff, ACCESS_PRESENT | ACCESS_DPL_0 | ACCESS_CODE_OR_DATA | ACCESS_RW, 0b1100);
    
    // 0x18: Ring 3 / Code
    GDT_ENTRIES.lock()[3] = GDTEntry::new(0, 0xffff_ffff, ACCESS_PRESENT | ACCESS_DPL_3 | ACCESS_CODE_OR_DATA | ACCESS_EXECUTABLE | ACCESS_RW , 0b1100);
    
    // 0x20: Ring 3 / Data
    GDT_ENTRIES.lock()[4] = GDTEntry::new(0, 0xffff_ffff, ACCESS_PRESENT | ACCESS_DPL_3 | ACCESS_CODE_OR_DATA | ACCESS_RW, 0b1100);

    let entries = GDT_ENTRIES.lock();

    unsafe {
        x86::dtables::lgdt(&x86::dtables::DescriptorTablePointer {
            limit: (core::mem::size_of::<GDTEntry>() * entries.len() - 1) as u16,
            base: entries.as_ptr()
        })
    };
}
