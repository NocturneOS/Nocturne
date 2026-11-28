#![no_std]

use noct_logger::qemu_log;

use crate::lapic::Lapic;

pub mod ioapic;
pub mod lapic;

struct SyncLapic {
    inner: spin::Once<Lapic>,
}

impl SyncLapic {
    pub const fn new() -> Self {
        Self {
            inner: spin::Once::new(),
        }
    }
}

impl noct_interrupts::InterruptController for SyncLapic {
    fn eoi(&self, _interrupt_nr: u8) {
        if let Some(lapic) = self.inner.get() {
            lapic.write(0xB0, 0x00);
        }
    }
}

static LAPIC: SyncLapic = SyncLapic::new();

pub fn init() {
    let ioapic = match ioapic::find() {
        Ok(x) => x,
        Err(e) => {
            qemu_log!("Failed to initialize APIC, no IOAPIC found! ({e:?})");
            return;
        }
    };

    noct_pic::disable();

    let lapic = LAPIC.inner.call_once(|| Lapic::init());

    // Software-enable LAPIC (flag 0x100 + spurious vector 0xFF)
    lapic.write(0xF0, 0x1FF);

    let ver = ioapic.read(ioapic::REG_VER) & 0xff;

    qemu_log!("I/O APIC VERSION: {ver:x?}");

    ioapic::post_init(&ioapic).expect("Failed to post-init APIC!");

    noct_interrupts::set_interrupt_controller(&LAPIC);

    qemu_log!("APIC initialized!");
    // todo!("Post initialize APIC!");
}
