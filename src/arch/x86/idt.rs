use spin::Mutex;

const PRESENT: u8 = 1 << 7;

const DPL_0: u8 = 0 << 5;
const DPL_3: u8 = 3 << 5;

const GATE_TASK: u8 = 0b0101;
const GATE_16_INTERRUPT: u8 = 0b0110;
const GATE_16_TRAP: u8 = 0b0111;
const GATE_32_INTERRUPT: u8 = 0b1110;
const GATE_32_TRAP: u8 = 0b1111;

#[repr(C, packed(1))]
struct IDTEntry {
    base_low: u16,
    selector: u16,
    reserved_1: u8,
    flags: u8,
    base_high: u16,
    #[cfg(target_arch = "x86_64")]
    base_higher: u32,
    #[cfg(target_arch = "x86_64")]
    reserved_2: u32,
}

impl IDTEntry {
    pub fn new(base: usize, selector: u16, flags: u8) -> Self {
        Self {
            base_low: (base & 0xffff) as u16,
            selector,
            reserved_1: 0,
            flags,
            base_high: ((base >> 16) & 0xffff) as u16,
            #[cfg(target_arch = "x86_64")]
            base_higher: ((base >> 32) & 0xffffffff) as u32,
            #[cfg(target_arch = "x86_64")]
            reserved_2: 0
        }
    }

    #[cfg(target_arch = "x86_64")]
    pub fn set_ist(&mut self, ist: u8) {
        self.reserved_1 = ist & 0b111;
    }
}

static IDT_ENTRIES: Mutex<[IDTEntry; 256]> = unsafe { core::mem::zeroed() };

#[rustfmt::skip]
unsafe extern "C" {
    fn isr0();
    fn isr1();
    fn isr2();
    fn isr3();
    fn isr4();
    fn isr5();
    fn isr6();
    fn isr7();
    fn isr8();
    fn isr9();
    fn isr10();
    fn isr11();
    fn isr12();
    fn isr13();
    fn isr14();
    fn isr15();
    fn isr16();
    fn isr17();
    fn isr18();
    fn isr19();
    fn isr20();
    fn isr21();
    fn isr22();
    fn isr23();
    fn isr24();
    fn isr25();
    fn isr26();
    fn isr27();
    fn isr28();
    fn isr29();
    fn isr30();
    fn isr31();

    fn irq0();
    fn irq1();
    fn irq2();
    fn irq3();
    fn irq4();
    fn irq5();
    fn irq6();
    fn irq7();
    fn irq8();
    fn irq9();
    fn irq10();
    fn irq11();
    fn irq12();
    fn irq13();
    fn irq14();
    fn irq15();

    fn isr80();

}

#[rustfmt::skip]
#[allow(clippy::identity_op)]
pub fn init() {
    let mut bind = IDT_ENTRIES.lock();

    bind[0] = IDTEntry::new(isr0 as *const () as _, 0x08, PRESENT | DPL_0 | GATE_32_TRAP);
    bind[1] = IDTEntry::new(isr1 as *const () as _, 0x08, PRESENT | DPL_0 | GATE_32_TRAP);
    bind[2] = IDTEntry::new(isr2 as *const () as _, 0x08, PRESENT | DPL_0 | GATE_32_TRAP);
    bind[3] = IDTEntry::new(isr3 as *const () as _, 0x08, PRESENT | DPL_0 | GATE_32_TRAP);
    bind[4] = IDTEntry::new(isr4 as *const () as _, 0x08, PRESENT | DPL_0 | GATE_32_TRAP);
    bind[5] = IDTEntry::new(isr5 as *const () as _, 0x08, PRESENT | DPL_0 | GATE_32_TRAP);
    bind[6] = IDTEntry::new(isr6 as *const () as _, 0x08, PRESENT | DPL_0 | GATE_32_TRAP);
    bind[7] = IDTEntry::new(isr7 as *const () as _, 0x08, PRESENT | DPL_0 | GATE_32_TRAP);
    bind[8] = IDTEntry::new(isr8 as *const () as _, 0x08, PRESENT | DPL_0 | GATE_32_TRAP);
    bind[9] = IDTEntry::new(isr9 as *const () as _, 0x08, PRESENT | DPL_0 | GATE_32_TRAP);
    bind[10] = IDTEntry::new(isr10 as *const () as _, 0x08, PRESENT | DPL_0 | GATE_32_TRAP);
    bind[11] = IDTEntry::new(isr11 as *const () as _, 0x08, PRESENT | DPL_0 | GATE_32_TRAP);
    bind[12] = IDTEntry::new(isr12 as *const () as _, 0x08, PRESENT | DPL_0 | GATE_32_TRAP);
    bind[13] = IDTEntry::new(isr13 as *const () as _, 0x08, PRESENT | DPL_0 | GATE_32_TRAP);
    bind[14] = IDTEntry::new(isr14 as *const () as _, 0x08, PRESENT | DPL_0 | GATE_32_TRAP);
    bind[15] = IDTEntry::new(isr15 as *const () as _, 0x08, PRESENT | DPL_0 | GATE_32_TRAP);
    bind[16] = IDTEntry::new(isr16 as *const () as _, 0x08, PRESENT | DPL_0 | GATE_32_TRAP);
    bind[17] = IDTEntry::new(isr17 as *const () as _, 0x08, PRESENT | DPL_0 | GATE_32_TRAP);
    bind[18] = IDTEntry::new(isr18 as *const () as _, 0x08, PRESENT | DPL_0 | GATE_32_TRAP);
    bind[19] = IDTEntry::new(isr19 as *const () as _, 0x08, PRESENT | DPL_0 | GATE_32_TRAP);
    bind[20] = IDTEntry::new(isr20 as *const () as _, 0x08, PRESENT | DPL_0 | GATE_32_TRAP);
    bind[21] = IDTEntry::new(isr21 as *const () as _, 0x08, PRESENT | DPL_0 | GATE_32_TRAP);
    bind[22] = IDTEntry::new(isr22 as *const () as _, 0x08, PRESENT | DPL_0 | GATE_32_TRAP);
    bind[23] = IDTEntry::new(isr23 as *const () as _, 0x08, PRESENT | DPL_0 | GATE_32_TRAP);
    bind[24] = IDTEntry::new(isr24 as *const () as _, 0x08, PRESENT | DPL_0 | GATE_32_TRAP);
    bind[25] = IDTEntry::new(isr25 as *const () as _, 0x08, PRESENT | DPL_0 | GATE_32_TRAP);
    bind[26] = IDTEntry::new(isr26 as *const () as _, 0x08, PRESENT | DPL_0 | GATE_32_TRAP);
    bind[27] = IDTEntry::new(isr27 as *const () as _, 0x08, PRESENT | DPL_0 | GATE_32_TRAP);
    bind[28] = IDTEntry::new(isr28 as *const () as _, 0x08, PRESENT | DPL_0 | GATE_32_TRAP);
    bind[29] = IDTEntry::new(isr29 as *const () as _, 0x08, PRESENT | DPL_0 | GATE_32_TRAP);
    bind[30] = IDTEntry::new(isr30 as *const () as _, 0x08, PRESENT | DPL_0 | GATE_32_TRAP);
    bind[31] = IDTEntry::new(isr31 as *const () as _, 0x08, PRESENT | DPL_0 | GATE_32_TRAP);

    #[cfg(target_arch = "x86_64")]
    for idx in 0..32 {
        bind[idx].set_ist(1);
    }

    bind[32 + 0] = IDTEntry::new(irq0 as *const () as _, 0x08, PRESENT | DPL_0 | GATE_32_INTERRUPT);
    bind[32 + 1] = IDTEntry::new(irq1 as *const () as _, 0x08, PRESENT | DPL_0 | GATE_32_INTERRUPT);
    bind[32 + 2] = IDTEntry::new(irq2 as *const () as _, 0x08, PRESENT | DPL_0 | GATE_32_INTERRUPT);
    bind[32 + 3] = IDTEntry::new(irq3 as *const () as _, 0x08, PRESENT | DPL_0 | GATE_32_INTERRUPT);
    bind[32 + 4] = IDTEntry::new(irq4 as *const () as _, 0x08, PRESENT | DPL_0 | GATE_32_INTERRUPT);
    bind[32 + 5] = IDTEntry::new(irq5 as *const () as _, 0x08, PRESENT | DPL_0 | GATE_32_INTERRUPT);
    bind[32 + 6] = IDTEntry::new(irq6 as *const () as _, 0x08, PRESENT | DPL_0 | GATE_32_INTERRUPT);
    bind[32 + 7] = IDTEntry::new(irq7 as *const () as _, 0x08, PRESENT | DPL_0 | GATE_32_INTERRUPT);
    bind[32 + 8] = IDTEntry::new(irq8 as *const () as _, 0x08, PRESENT | DPL_0 | GATE_32_INTERRUPT);
    bind[32 + 9] = IDTEntry::new(irq9 as *const () as _, 0x08, PRESENT | DPL_0 | GATE_32_INTERRUPT);
    bind[32 + 10] = IDTEntry::new(irq10 as *const () as _, 0x08, PRESENT | DPL_0 | GATE_32_INTERRUPT);
    bind[32 + 11] = IDTEntry::new(irq11 as *const () as _, 0x08, PRESENT | DPL_0 | GATE_32_INTERRUPT);
    bind[32 + 12] = IDTEntry::new(irq12 as *const () as _, 0x08, PRESENT | DPL_0 | GATE_32_INTERRUPT);
    bind[32 + 13] = IDTEntry::new(irq13 as *const () as _, 0x08, PRESENT | DPL_0 | GATE_32_INTERRUPT);
    bind[32 + 14] = IDTEntry::new(irq14 as *const () as _, 0x08, PRESENT | DPL_0 | GATE_32_INTERRUPT);
    bind[32 + 15] = IDTEntry::new(irq15 as *const () as _, 0x08, PRESENT | DPL_0 | GATE_32_INTERRUPT);

    bind[128] = IDTEntry::new(isr80 as *const () as _, 0x08, PRESENT | DPL_3 | GATE_32_TRAP);

    let entries = bind;

    unsafe { x86::dtables::lidt(&x86::dtables::DescriptorTablePointer {
        limit: (core::mem::size_of::<IDTEntry>() * entries.len() - 1) as _,
        base: entries.as_ptr(),
    }) };
}
