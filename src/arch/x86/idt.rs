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
    always0: u8,
    flags: u8,
    base_high: u16,
}

impl IDTEntry {
    pub fn new(base: u32, selector: u16, flags: u8) -> Self {
        Self {
            base_low: (base & 0xffff) as u16,
            selector,
            always0: 0,
            flags,
            base_high: ((base >> 16) & 0xffff) as u16,
        }
    }
}

static IDT_ENTRIES: spin::Mutex<[IDTEntry; 256]> = unsafe { core::mem::zeroed() };

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
pub fn init() {
    IDT_ENTRIES.lock()[0] = IDTEntry::new(isr0 as *const () as _, 0x08, PRESENT | DPL_0 | GATE_32_TRAP);
    IDT_ENTRIES.lock()[1] = IDTEntry::new(isr1 as *const () as _, 0x08, PRESENT | DPL_0 | GATE_32_TRAP);
    IDT_ENTRIES.lock()[2] = IDTEntry::new(isr2 as *const () as _, 0x08, PRESENT | DPL_0 | GATE_32_TRAP);
    IDT_ENTRIES.lock()[3] = IDTEntry::new(isr3 as *const () as _, 0x08, PRESENT | DPL_0 | GATE_32_TRAP);
    IDT_ENTRIES.lock()[4] = IDTEntry::new(isr4 as *const () as _, 0x08, PRESENT | DPL_0 | GATE_32_TRAP);
    IDT_ENTRIES.lock()[5] = IDTEntry::new(isr5 as *const () as _, 0x08, PRESENT | DPL_0 | GATE_32_TRAP);
    IDT_ENTRIES.lock()[6] = IDTEntry::new(isr6 as *const () as _, 0x08, PRESENT | DPL_0 | GATE_32_TRAP);
    IDT_ENTRIES.lock()[7] = IDTEntry::new(isr7 as *const () as _, 0x08, PRESENT | DPL_0 | GATE_32_TRAP);
    IDT_ENTRIES.lock()[8] = IDTEntry::new(isr8 as *const () as _, 0x08, PRESENT | DPL_0 | GATE_32_TRAP);
    IDT_ENTRIES.lock()[9] = IDTEntry::new(isr9 as *const () as _, 0x08, PRESENT | DPL_0 | GATE_32_TRAP);
    IDT_ENTRIES.lock()[10] = IDTEntry::new(isr10 as *const () as _, 0x08, PRESENT | DPL_0 | GATE_32_TRAP);
    IDT_ENTRIES.lock()[11] = IDTEntry::new(isr11 as *const () as _, 0x08, PRESENT | DPL_0 | GATE_32_TRAP);
    IDT_ENTRIES.lock()[12] = IDTEntry::new(isr12 as *const () as _, 0x08, PRESENT | DPL_0 | GATE_32_TRAP);
    IDT_ENTRIES.lock()[13] = IDTEntry::new(isr13 as *const () as _, 0x08, PRESENT | DPL_0 | GATE_32_TRAP);
    IDT_ENTRIES.lock()[14] = IDTEntry::new(isr14 as *const () as _, 0x08, PRESENT | DPL_0 | GATE_32_TRAP);
    IDT_ENTRIES.lock()[15] = IDTEntry::new(isr15 as *const () as _, 0x08, PRESENT | DPL_0 | GATE_32_TRAP);
    IDT_ENTRIES.lock()[16] = IDTEntry::new(isr16 as *const () as _, 0x08, PRESENT | DPL_0 | GATE_32_TRAP);
    IDT_ENTRIES.lock()[17] = IDTEntry::new(isr17 as *const () as _, 0x08, PRESENT | DPL_0 | GATE_32_TRAP);
    IDT_ENTRIES.lock()[18] = IDTEntry::new(isr18 as *const () as _, 0x08, PRESENT | DPL_0 | GATE_32_TRAP);
    IDT_ENTRIES.lock()[19] = IDTEntry::new(isr19 as *const () as _, 0x08, PRESENT | DPL_0 | GATE_32_TRAP);
    IDT_ENTRIES.lock()[20] = IDTEntry::new(isr20 as *const () as _, 0x08, PRESENT | DPL_0 | GATE_32_TRAP);
    IDT_ENTRIES.lock()[21] = IDTEntry::new(isr21 as *const () as _, 0x08, PRESENT | DPL_0 | GATE_32_TRAP);
    IDT_ENTRIES.lock()[22] = IDTEntry::new(isr22 as *const () as _, 0x08, PRESENT | DPL_0 | GATE_32_TRAP);
    IDT_ENTRIES.lock()[23] = IDTEntry::new(isr23 as *const () as _, 0x08, PRESENT | DPL_0 | GATE_32_TRAP);
    IDT_ENTRIES.lock()[24] = IDTEntry::new(isr24 as *const () as _, 0x08, PRESENT | DPL_0 | GATE_32_TRAP);
    IDT_ENTRIES.lock()[25] = IDTEntry::new(isr25 as *const () as _, 0x08, PRESENT | DPL_0 | GATE_32_TRAP);
    IDT_ENTRIES.lock()[26] = IDTEntry::new(isr26 as *const () as _, 0x08, PRESENT | DPL_0 | GATE_32_TRAP);
    IDT_ENTRIES.lock()[27] = IDTEntry::new(isr27 as *const () as _, 0x08, PRESENT | DPL_0 | GATE_32_TRAP);
    IDT_ENTRIES.lock()[28] = IDTEntry::new(isr28 as *const () as _, 0x08, PRESENT | DPL_0 | GATE_32_TRAP);
    IDT_ENTRIES.lock()[29] = IDTEntry::new(isr29 as *const () as _, 0x08, PRESENT | DPL_0 | GATE_32_TRAP);
    IDT_ENTRIES.lock()[30] = IDTEntry::new(isr30 as *const () as _, 0x08, PRESENT | DPL_0 | GATE_32_TRAP);
    IDT_ENTRIES.lock()[31] = IDTEntry::new(isr31 as *const () as _, 0x08, PRESENT | DPL_0 | GATE_32_TRAP);

    IDT_ENTRIES.lock()[32 + 0] = IDTEntry::new(irq0 as *const () as _, 0x08, PRESENT | DPL_0 | GATE_32_INTERRUPT);
    IDT_ENTRIES.lock()[32 + 1] = IDTEntry::new(irq1 as *const () as _, 0x08, PRESENT | DPL_0 | GATE_32_INTERRUPT);
    IDT_ENTRIES.lock()[32 + 2] = IDTEntry::new(irq2 as *const () as _, 0x08, PRESENT | DPL_0 | GATE_32_INTERRUPT);
    IDT_ENTRIES.lock()[32 + 3] = IDTEntry::new(irq3 as *const () as _, 0x08, PRESENT | DPL_0 | GATE_32_INTERRUPT);
    IDT_ENTRIES.lock()[32 + 4] = IDTEntry::new(irq4 as *const () as _, 0x08, PRESENT | DPL_0 | GATE_32_INTERRUPT);
    IDT_ENTRIES.lock()[32 + 5] = IDTEntry::new(irq5 as *const () as _, 0x08, PRESENT | DPL_0 | GATE_32_INTERRUPT);
    IDT_ENTRIES.lock()[32 + 6] = IDTEntry::new(irq6 as *const () as _, 0x08, PRESENT | DPL_0 | GATE_32_INTERRUPT);
    IDT_ENTRIES.lock()[32 + 7] = IDTEntry::new(irq7 as *const () as _, 0x08, PRESENT | DPL_0 | GATE_32_INTERRUPT);
    IDT_ENTRIES.lock()[32 + 8] = IDTEntry::new(irq8 as *const () as _, 0x08, PRESENT | DPL_0 | GATE_32_INTERRUPT);
    IDT_ENTRIES.lock()[32 + 9] = IDTEntry::new(irq9 as *const () as _, 0x08, PRESENT | DPL_0 | GATE_32_INTERRUPT);
    IDT_ENTRIES.lock()[32 + 10] = IDTEntry::new(irq10 as *const () as _, 0x08, PRESENT | DPL_0 | GATE_32_INTERRUPT);
    IDT_ENTRIES.lock()[32 + 11] = IDTEntry::new(irq11 as *const () as _, 0x08, PRESENT | DPL_0 | GATE_32_INTERRUPT);
    IDT_ENTRIES.lock()[32 + 12] = IDTEntry::new(irq12 as *const () as _, 0x08, PRESENT | DPL_0 | GATE_32_INTERRUPT);
    IDT_ENTRIES.lock()[32 + 13] = IDTEntry::new(irq13 as *const () as _, 0x08, PRESENT | DPL_0 | GATE_32_INTERRUPT);
    IDT_ENTRIES.lock()[32 + 14] = IDTEntry::new(irq14 as *const () as _, 0x08, PRESENT | DPL_0 | GATE_32_INTERRUPT);
    IDT_ENTRIES.lock()[32 + 15] = IDTEntry::new(irq15 as *const () as _, 0x08, PRESENT | DPL_0 | GATE_32_INTERRUPT);

    IDT_ENTRIES.lock()[128] = IDTEntry::new(isr80 as *const () as _, 0x08, PRESENT | DPL_3 | GATE_32_TRAP);

    let entries = IDT_ENTRIES.lock();

    unsafe { x86::dtables::lidt(&x86::dtables::DescriptorTablePointer {
        limit: (core::mem::size_of::<IDTEntry>() * entries.len() - 1) as _,
        base: entries.as_ptr(),
    }) };
}
