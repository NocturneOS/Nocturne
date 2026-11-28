use acpi::{
    AcpiError,
    sdt::madt::MadtEntry,
};
use noct_logger::qemu_log;
use noct_mem::paging::PageFlags;

#[derive(Debug)]
pub enum IoApicError {
    Acpi(AcpiError),
    NotFound,
}

pub const IOAPIC_REGSEL: u32 = 0x00;
pub const IOAPIC_DATA: u32 = 0x10;

pub const REG_ID: u32 = 0x00;
pub const REG_VER: u32 = 0x01;
pub const REG_ARB: u32 = 0x02;
pub const REG_REDTBL_BASE: u32 = 0x10;

pub struct IoApic {
    id: u8,
    base_addr: usize,
    gsi_base: usize,

    mem_handle: noct_mem::paging::MappingContext,
}

impl IoApic {
    fn select_register(&self, reg: u32) {
        let ptr = (self.base_addr + IOAPIC_REGSEL as usize) as *mut u32;

        unsafe { ptr.write_volatile(reg) };
    }

    pub fn read(&self, reg: u32) -> u32 {
        self.select_register(reg);

        let ptr = (self.base_addr + IOAPIC_DATA as usize) as *mut u32;

        unsafe { ptr.read_volatile() }
    }

    pub fn write(&self, reg: u32, value: u32) {
        self.select_register(reg);

        let ptr = (self.base_addr + IOAPIC_DATA as usize) as *mut u32;

        unsafe {
            ptr.write_volatile(value);
        }
    }
}

pub fn find() -> Result<IoApic, IoApicError> {
    let madt = noct_acpi::table::<acpi::sdt::madt::Madt>().map_err(IoApicError::Acpi)?;

    // TODO: Support multiple IOAPICs.
    // For now just select the first IOAPIC.
    let ioapic = madt
        .get()
        .entries()
        .filter(|x| matches!(x, MadtEntry::IoApic(_)))
        .map(|x| match x {
            MadtEntry::IoApic(io) => io,
            _ => unreachable!(),
        })
        .next()
        .ok_or(IoApicError::NotFound)?;

    let handle = noct_mem::paging::MappingContext::map(
        ioapic.io_apic_address as _,
        ioapic.io_apic_address as _,
        4096,
        PageFlags::Writeable,
    );

    Ok(IoApic {
        id: ioapic.io_apic_id,
        base_addr: ioapic.io_apic_address as _,
        gsi_base: ioapic.global_system_interrupt_base as _,
        mem_handle: handle,
    })
}

pub fn post_init(ioapic: &IoApic) -> Result<(), IoApicError> {
    let madt = noct_acpi::table::<acpi::sdt::madt::Madt>().map_err(IoApicError::Acpi)?;

    let isos = madt.get().entries().filter_map(|x| match x {
        MadtEntry::InterruptSourceOverride(iso) => Some(iso),
        _ => None,
    });

    // Remap entries defined in ISOs.
    for i in isos {
        let irq = i.irq;
        let gsi = i.global_system_interrupt;

        qemu_log!("Remapping IRQ source {irq} -> GSI: {gsi}");

        ioapic.write(REG_REDTBL_BASE + (gsi * 2), (32 + irq) as _);
        ioapic.write(REG_REDTBL_BASE + (gsi * 2) + 1, 0);
    }

    // Let's fill IOAPIC REDTBL with identity values.
    for i in 1..24 {
        let isr = ioapic.read(REG_REDTBL_BASE + (i * 2));

        if(isr & 0x10000) != 0 {
            qemu_log!("Identity map: {i}");

            ioapic.write(REG_REDTBL_BASE + (i * 2), (32 + i) as _);
            ioapic.write(REG_REDTBL_BASE + (i * 2) + 1, 0);
        }
    }

    Ok(())
}
