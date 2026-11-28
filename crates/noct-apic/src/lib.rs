#![no_std]

use core::{cell::OnceCell, ops::Deref};

use noct_logger::qemu_log;
use noct_sync::pseudosync::PseudoSync;

use crate::lapic::Lapic;

pub mod ioapic;
pub mod lapic;

struct SyncLapic {
    inner: PseudoSync<OnceCell<Lapic>>,
}

impl SyncLapic {
    pub const fn new() -> Self {
        Self {
            inner: PseudoSync::new(OnceCell::new()),
        }
    }
}

impl Deref for SyncLapic {
    type Target = PseudoSync<OnceCell<Lapic>>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl noct_interrupts::InterruptController for SyncLapic {
    fn eoi(&self, _interrupt_nr: u8) {
        self.get().get().unwrap().write(0xB0, 0x00);
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

    let lapic = unsafe { LAPIC.pseudo_lock().get_or_init(|| Lapic::init()) };

	// Software-enable LAPIC (flag 0x100 + spurious vector 0xFF)
    lapic.write(0xF0, 0x1FF);

    let ver = ioapic.read(ioapic::REG_VER) & 0xff;

    qemu_log!("I/O APIC VERSION: {ver:x?}");

    ioapic::post_init(&ioapic).expect("Failed to post-init APIC!");

    noct_interrupts::set_interrupt_controller(&LAPIC);

    qemu_log!("APIC initialized!");
    // todo!("Post initialize APIC!");
}
