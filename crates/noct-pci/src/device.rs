use crate::{bar::{BARType, PCIBar}};

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

impl PCIDevice {
    pub fn read16(&self, offset: u8) -> u16 {
        crate::read16(self.bus, self.slot, self.function, offset)
    }

    pub fn read32(&self, offset: u8) -> u32 {
        crate::read32(self.bus, self.slot, self.function, offset)
    }

    fn write_command(&self, value: u16) {
        crate::write16(self.bus, self.slot, self.function, 0x4, value);
    }

    fn read_command(&self) -> u16 {
        crate::read16(self.bus, self.slot, self.function, 0x4)
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
        crate::write(self.bus, self.slot, self.function, offset, value);
    }

    pub fn enable_bus_mastering(&self) {
        let command = self.read32(4);

        self.write(4, command | 0x05);
    }
}
