#![allow(static_mut_refs)]

use core::cell::OnceCell;

use alloc::vec::Vec;
use spin::{RwLock, RwLockReadGuard};
use x86::io::{inl, outl};

use crate::{qemu_log, time::get_uptime_millis as timestamp};

static PCI_ADDRESS_PORT: u16 = 0xCF8;
static PCI_DATA_PORT: u16 = 0xCFC;

static mut PCI_DEVICES: OnceCell<RwLock<Vec<PCIDevice>>> = OnceCell::new();

#[derive(Clone, Copy, Debug, Default)]
pub struct PCIDevice {
    pub vendor: u16,
    pub device: u16,

    pub bus: u8,
    pub slot: u8,
    pub function: u8,

    pub class: u8,
    pub subclass: u8,

    pub header_type: u8,
}

pub fn pci_read32(bus: u8, slot: u8, function: u8, offset: u8) -> u32 {
    let addr: u32 = ((bus as u32) << 16)
        | ((slot as u32) << 11)
        | ((function as u32) << 8)
        | (offset as u32)
        | 0x80000000; //yes, this line is copied from osdev

    unsafe {
        outl(PCI_ADDRESS_PORT, addr);

        inl(PCI_DATA_PORT)
    }
}

pub fn pci_read16(bus: u8, slot: u8, function: u8, offset: u8) -> u16 {
    let addr: u32 = ((bus as u32) << 16)
        | ((slot as u32) << 11)
        | ((function as u32) << 8)
        | ((offset & 0xFC) as u32)
        | 0x80000000; //yes, this line is copied from osdev

    unsafe {
        outl(PCI_ADDRESS_PORT, addr);

        (inl(PCI_DATA_PORT) >> ((offset & 2) * 8)) as u16
    }
}

pub fn pci_write(bus: u8, slot: u8, func: u8, offset: u8, value: u32) {
    let addr: u32 = ((bus as u32) << 16)
        | ((slot as u32) << 11)
        | ((func as u32) << 8)
        | ((offset as u32) & 0xfc)
        | 0x80000000;
    unsafe {
        outl(PCI_ADDRESS_PORT, addr);
        outl(PCI_DATA_PORT, value);
    }
}

pub fn pci_write16(bus: u8, slot: u8, func: u8, offset: u8, value: u16) {
    let addr: u32 = ((bus as u32) << 16)
        | ((slot as u32) << 11)
        | ((func as u32) << 8)
        | ((offset as u32) & 0xfc)
        | 0x80000000;
    unsafe {
        outl(PCI_ADDRESS_PORT, addr);
        outl(PCI_DATA_PORT, (value >> ((offset & 2) * 8)) as u32);
    }
}

#[derive(Debug, PartialEq)]
pub enum BARType {
    Memory = 0,
    IO = 1,
}

impl From<BARType> for u8 {
    fn from(val: BARType) -> Self {
        match val {
            BARType::Memory => 0,
            BARType::IO => 1,
        }
    }
}

#[derive(Debug)]
pub struct PCIBar {
    pub bar_type: BARType,
    pub address: usize,
    pub length: usize,
}

impl PCIDevice {
    pub fn read16(&self, offset: u8) -> u16 {
        pci_read16(self.bus, self.slot, self.function, offset)
    }

    pub fn read32(&self, offset: u8) -> u32 {
        pci_read32(self.bus, self.slot, self.function, offset)
    }

    fn write_command(&self, value: u16) {
        pci_write16(self.bus, self.slot, self.function, 0x4, value);
    }

    fn read_command(&self) -> u16 {
        pci_read16(self.bus, self.slot, self.function, 0x4)
    }

    pub fn read_bar(&self, bar: u8) -> Option<PCIBar> {
        if bar > 5 {
            return None;
        }

        let raw = self.read32(0x10 + (bar * 4));
        let bar_type = if raw & 1 == 1 {
            BARType::IO
        } else {
            BARType::Memory
        };

        let address = match bar_type {
            BARType::IO => raw & 0xffff_fffc,
            BARType::Memory => raw & 0xffff_fff0,
        };

        let orig_cmd = self.read_command();
        self.write_command(orig_cmd & 0xfffc);

        self.write(0x10 + (bar * 4), 0xffff_ffff);
        let meta = self.read32(0x10 + (bar * 4));
        let size = match bar_type {
            BARType::IO => !(meta & 0xffff_fffc),
            BARType::Memory => !(meta & 0xffff_fff0),
        } + 1;

        self.write(0x10 + (bar * 4), raw);
        self.write_command(orig_cmd);

        Some(PCIBar {
            bar_type,
            address: address as _,
            length: size as _,
        })
    }

    pub fn write(&self, offset: u8, value: u32) {
        pci_write(self.bus, self.slot, self.function, offset, value);
    }
}

pub fn find_device(vendor: u16, device: u16) -> Option<PCIDevice> {
    let devs = devices();

    devs.iter()
        .find(|x| x.vendor == vendor && x.device == device)
        .cloned()
}

pub fn find_device_by_class_and_subclass(class: u8, subclass: u8) -> Option<PCIDevice> {
    let devs = devices();

    devs.iter()
        .find(|a| a.class == class && a.subclass == subclass)
        .cloned()
}

#[inline(always)]
pub fn pci_get_vendor(bus: u8, slot: u8, function: u8) -> u16 {
    pci_read16(bus, slot, function, 0)
}

pub fn scan() {
    unsafe {
        let devices = PCI_DEVICES.get_or_init(|| RwLock::new(Vec::new()));

        let mut guard = devices.write();
        guard.clear();
    }

    let start_time = timestamp();

    for bus in 0..=255 {
        for slot in 0..=31 {
            let mut hdrtype: u8 = 0;

            let mut vendor: u16 = pci_get_vendor(bus, slot, 0);

            if vendor != 0xFFFF {
                let clid: u8 = ((pci_read16(bus, slot, 0, 0xA) >> 8) & 0xff) as u8;
                let sclid: u8 = ((pci_read16(bus, slot, 0, 0xA)) & 0xff) as u8;
                let device: u16 = pci_read16(bus, slot, 0, 0x2);

                hdrtype = (pci_read16(bus, slot, 0, 0xE) & 0xff) as u8;

                unsafe {
                    let dev = PCIDevice {
                        class: clid,
                        subclass: sclid,
                        bus,
                        slot,
                        function: 0,
                        header_type: hdrtype,
                        vendor,
                        device,
                    };

                    // qemu_log!("{:?}", &dev);

                    PCI_DEVICES.get_mut().unwrap().write().push(dev);
                }
            }

            if (hdrtype & 0x80) != 0 {
                for func in 1..8 {
                    vendor = pci_get_vendor(bus, slot, func);

                    if vendor != 0xFFFF {
                        let clid = ((pci_read16(bus, slot, func, 0xA) >> 8) & 0xff) as u8;
                        let sclid = (pci_read16(bus, slot, func, 0xA) & 0xff) as u8;
                        let device = pci_read16(bus, slot, func, 0x2);

                        unsafe {
                            let dev = PCIDevice {
                                class: clid,
                                subclass: sclid,
                                bus,
                                slot,
                                function: func,
                                header_type: hdrtype,
                                vendor,
                                device,
                            };

                            // qemu_log!("{:?}", &dev);

                            PCI_DEVICES.get_mut().unwrap().write().push(dev);
                        }
                    }
                }
            }
        }
    }

    let elapsed = timestamp() - start_time;

    qemu_log!("PCI: scan end in {} ms", elapsed);

    unsafe {
        qemu_log!(
            "PCI: Found {} devices",
            PCI_DEVICES.get().unwrap().read().len()
        );
    }
}

pub fn devices<'a>() -> RwLockReadGuard<'a, Vec<PCIDevice>> {
    unsafe { PCI_DEVICES.get().unwrap().read() }
}

pub fn get_device(bus: u8, slot: u8, func: u8) -> Option<PCIDevice> {
    let devices = devices();
    for dev in devices.iter() {
        if dev.bus == bus && dev.slot == slot && dev.function == func {
            return Some(*dev);
        }
    }

    None
}