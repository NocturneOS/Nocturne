#![no_std]

use core::{alloc::Layout, ptr::NonNull};

use acpi::sdt::hpet::HpetTable;
use noct_logger::qemu_log;
use noct_mem::paging::PageFlags;

extern crate alloc;

#[derive(Clone)]
struct ACPIHandler;

impl acpi::Handler for ACPIHandler {
    unsafe fn map_physical_region<T>(
        &self,
        physical_address: usize,
        size: usize,
    ) -> acpi::PhysicalMapping<Self, T> {
        // If mapping below kernel is performed, it's better not to map pages ...
        // Because it's already mapped on higher-half!
        if physical_address < 0x100_000 {
            return acpi::PhysicalMapping {
                physical_start: physical_address,
                virtual_start: NonNull::new((noct_spec::KERNEL_BASE + physical_address) as *mut T)
                    .unwrap(),
                region_length: size,
                mapped_length: size,
                handler: ACPIHandler,
            };
        }

        let mapped_length = {
            let start = physical_address & !0xfff;
            let end = (physical_address + size) & !0xfff;

            (end - start).max(0x1000)
        };

        let allocation = unsafe {
            noct_mem::heap::allocate_no_map(Layout::from_size_align_unchecked(mapped_length, 4096))
        };

        assert!(!allocation.is_null());

        let offset = physical_address & 0xfff;

        noct_mem::paging::map_pages(
            physical_address & !0xfff,
            allocation.addr(),
            mapped_length,
            PageFlags::Writeable,
        );

        acpi::PhysicalMapping {
            physical_start: physical_address,
            virtual_start: unsafe { NonNull::new(allocation.add(offset).cast::<T>()).unwrap() },
            region_length: size,
            mapped_length,
            handler: ACPIHandler,
        }

        // panic!("Physical memory: {:#x} (size: {:#x})", physical_address, size);
    }

    fn unmap_physical_region<T>(region: &acpi::PhysicalMapping<Self, T>) {
        if region.physical_start < 0x100_000 {
            return;
        }

        let layout = unsafe { Layout::from_size_align_unchecked(region.mapped_length, 4096) };
        let allocation = (region.virtual_start.as_ptr().addr() & !0xfff) as *mut u8;

        // Pages will be automatically unmapped
        noct_mem::paging::unmap_pages(allocation.addr(), region.mapped_length);

        unsafe { alloc::alloc::dealloc(allocation, layout) };

        // panic!(
        //     "Unmapping physical memory: {:#x} (size: {:#x})",
        //     region.physical_start, region.mapped_length
        // );
    }

    fn read_u8(&self, address: usize) -> u8 {
        unsafe { (address as *const u8).read_volatile() }
    }

    fn read_u16(&self, address: usize) -> u16 {
        unsafe { (address as *const u16).read_volatile() }
    }

    fn read_u32(&self, address: usize) -> u32 {
        unsafe { (address as *const u32).read_volatile() }
    }

    fn read_u64(&self, address: usize) -> u64 {
        unsafe { (address as *const u64).read_volatile() }
    }

    fn write_u8(&self, address: usize, value: u8) {
        unsafe { (address as *mut u8).write_volatile(value) }
    }

    fn write_u16(&self, address: usize, value: u16) {
        unsafe { (address as *mut u16).write_volatile(value) }
    }

    fn write_u32(&self, address: usize, value: u32) {
        unsafe { (address as *mut u32).write_volatile(value) }
    }

    fn write_u64(&self, address: usize, value: u64) {
        unsafe { (address as *mut u64).write_volatile(value) }
    }

    fn read_io_u8(&self, port: u16) -> u8 {
        unsafe { x86::io::inb(port) }
    }

    fn read_io_u16(&self, port: u16) -> u16 {
        unsafe { x86::io::inw(port) }
    }

    fn read_io_u32(&self, port: u16) -> u32 {
        unsafe { x86::io::inl(port) }
    }

    fn write_io_u8(&self, port: u16, value: u8) {
        unsafe { x86::io::outb(port, value) }
    }

    fn write_io_u16(&self, port: u16, value: u16) {
        unsafe { x86::io::outw(port, value) }
    }

    fn write_io_u32(&self, port: u16, value: u32) {
        unsafe { x86::io::outl(port, value) }
    }

    fn read_pci_u8(&self, address: acpi::PciAddress, offset: u16) -> u8 {
        todo!()
    }

    fn read_pci_u16(&self, address: acpi::PciAddress, offset: u16) -> u16 {
        todo!()
    }

    fn read_pci_u32(&self, address: acpi::PciAddress, offset: u16) -> u32 {
        todo!()
    }

    fn write_pci_u8(&self, address: acpi::PciAddress, offset: u16, value: u8) {
        todo!()
    }

    fn write_pci_u16(&self, address: acpi::PciAddress, offset: u16, value: u16) {
        todo!()
    }

    fn write_pci_u32(&self, address: acpi::PciAddress, offset: u16, value: u32) {
        todo!()
    }

    fn nanos_since_boot(&self) -> u64 {
        todo!()
    }

    fn stall(&self, microseconds: u64) {
        todo!()
    }

    fn sleep(&self, milliseconds: u64) {
        todo!()
    }
}

pub fn init() {
    let result = unsafe { acpi::rsdp::Rsdp::search_for_on_bios(ACPIHandler) };

    if let Ok(rsdp) = result {
        let tables = unsafe {
            acpi::AcpiTables::from_rsdt(ACPIHandler, rsdp.revision(), rsdp.rsdt_address() as _)
        };

        if let Ok(tables) = tables {
            let hpet = tables.find_table::<HpetTable>();

            qemu_log!("HPET: {hpet:?}");
        }

    } else {
        panic!("ACPI RSDP not found");
    }
}
