use lazy_static::lazy_static;
use x86::{Ring, segmentation::SegmentSelector};

use crate::{arch::x86::gdt, tools::pseudosync::PseudoSync};

#[repr(C, packed)]
pub struct TSSEntry {
    pub prev_tss: u32,
    pub esp0: u32,
    pub ss0: u32,
    pub esp1: u32,
    pub ss1: u32,
    pub esp2: u32,
    pub ss2: u32,
    pub cr3: u32,
    pub eip: u32,
    pub eflags: u32,
    pub eax: u32,
    pub ecx: u32,
    pub edx: u32,
    pub ebx: u32,
    pub esp: u32,
    pub ebp: u32,
    pub esi: u32,
    pub edi: u32,
    pub es: u32,
    pub cs: u32,
    pub ss: u32,
    pub ds: u32,
    pub fs: u32,
    pub gs: u32,
    pub ldtr: u32,
    pub trap: u16,
    pub iomap_base: u16,
}

pub const TSS_KERNEL_STACK_SIZE: usize = 0x1000;

#[unsafe(no_mangle)]
static BSP_TSS: PseudoSync<TSSEntry> = unsafe { core::mem::zeroed() };
static BSP_TSS_KERNEL_STACK: [usize; TSS_KERNEL_STACK_SIZE / core::mem::size_of::<usize>()] = [0; TSS_KERNEL_STACK_SIZE / core::mem::size_of::<usize>()];

// TODO: Initialize the TSS!
pub fn init() {
    unsafe {
        let tss = BSP_TSS.get_mut();

        tss.ss0 = 0x10;
        tss.esp0 = (BSP_TSS_KERNEL_STACK.as_ptr().addr() + (TSS_KERNEL_STACK_SIZE / core::mem::size_of::<usize>())) as u32;

        tss.cs = 0x08 | 3;
        tss.ss = 0x10 | 3;
        tss.ds = 0x10 | 3;
        tss.es = 0x10 | 3;
        tss.fs = 0x10 | 3;
        tss.gs = 0x10 | 3;

        *gdt::GDT_ENTRIES.nth(5) = gdt::GDTEntry::new(
            (tss as *mut TSSEntry).addr() as u32,
            (core::mem::size_of::<TSSEntry>() - 1) as u32,
            gdt::ACCESS_PRESENT | gdt::ACCESS_EXECUTABLE | gdt::ACCESS_ACCESSED,
            0,
        );

        x86::task::load_tr(SegmentSelector::new(5, Ring::Ring0));
    }
}

pub fn get_tss_stack_addr() -> usize {
    BSP_TSS_KERNEL_STACK.as_ptr().addr() + (TSS_KERNEL_STACK_SIZE / core::mem::size_of::<usize>())
}