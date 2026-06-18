use lazy_static::lazy_static;
use noct_sync::pseudosync::PseudoSync;
use x86::{Ring, segmentation::SegmentSelector};

use crate::x86::gdt;

pub use crate::x86::tss::*;

#[repr(C, packed)]
pub struct TSSEntry {
    reserved: u32,
    rsp0: u64,
    rsp1: u64,
    rsp2: u64,
    reserved_2: u64,
    ist1: u64,
    ist2: u64,
    ist3: u64,
    ist4: u64,
    ist5: u64,
    ist6: u64,
    ist7: u64,
    reserved_3: u64,
    reserved_4: u16,
    iopb: u16,
}

lazy_static! {
    static ref BSP_TSS: PseudoSync<TSSEntry> = unsafe { core::mem::zeroed() };
}

const DUMB_STACK_SIZE: usize = 0x1000;

// TODO: Dynamically allocate the stack!
#[repr(align(16))]
struct AlignedStack([u8; DUMB_STACK_SIZE]);

static DUMB_STACK: AlignedStack = AlignedStack([0; DUMB_STACK_SIZE]);

pub fn init() {
    unsafe {
        BSP_TSS.get_mut().iopb = core::mem::size_of::<TSSEntry>() as u16;
        BSP_TSS.get_mut().ist1 = DUMB_STACK.0.as_ptr().add(DUMB_STACK_SIZE).addr() as u64;
    }

    let base = (BSP_TSS.get() as *const TSSEntry).addr();
    let limit = core::mem::size_of::<TSSEntry>() - 1;

    // qemu_log!("TSS BASE: {base:#x?}; TSS LIMIT: {limit:#x?}");

    *gdt::GDT_ENTRIES.nth(5) = gdt::GDTEntry::new(
        base as u32,
        limit as u32,
        gdt::ACCESS_PRESENT | gdt::ACCESS_EXECUTABLE | gdt::ACCESS_ACCESSED,
        gdt::FLAG_LONGMODE,
    );

    // Write the upper part of system descriptor by utilizing next GDT entry
    // The Long-Mode GDT entry is 16 bytes long, but only when defining TSS or LDT.
    // We're defining TSS, so we have to write 16-bit GDT.
    // The other 8 bytes are divided by two fields: [31..0] base_highest (the high part of 64-bit base) and [63..32] is a reserved field.
    let upper_part = gdt::GDT_ENTRIES.nth_ptr(6) as *mut u32;
    unsafe {
        upper_part.add(0).write((base >> 32) as u32);
        upper_part.add(1).write(0);
    }

    // Fifth index in the GDT: 0x08 * 5 = 0x28.
    unsafe { x86::task::load_tr(SegmentSelector::new(5, Ring::Ring0)) };
}
