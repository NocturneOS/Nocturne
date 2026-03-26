use core::ffi::CStr;

use crate::alloc::borrow::ToOwned;
use crate::alloc::vec::Vec;
use crate::alloc::string::String;

const SMBIOS_32_ANCHOR: &[u8] = b"_SM_";

#[repr(C, packed)]
#[derive(Debug)]
pub struct SMBIOS32Header {
    pub anchor_string: [u8; 4],
    pub entry_point_checksum: u8,
    pub entry_point_length: u8,
    pub version_major: u8,
    pub version_minor: u8,
    pub structure_max_size: u16,
    pub entry_point_revision: u8,
    pub formatted_area: [u8; 5],
    pub intermediate_anchor_string: [u8; 5],
    pub intermediate_checksum: u8,
    pub structure_table_length: u16,
    pub structure_table_addr: u32,
    pub number_of_structs: u16,
    pub bcd_revision: u8,
}

#[repr(C, packed)]
#[derive(Debug)]
pub struct SMBIOSEntryHeader {
    header_type: u8,
    length: u8,
    handle: u16,
}

#[allow(dead_code)]
#[derive(Debug)]
pub struct SMBIOS {
    address: usize,
    header: SMBIOS32Header,
}

#[derive(Debug)]
pub enum SMBIOSEntry {
    BIOS {
        vendor: String,
        firmware_version: String,
        segment_address: u16,
        release_date: String,
        rom_size: usize,
    },
    System {
        manufacturer: String,
        product_name: String,
        version: String,
        serial_number: String,
        uuid: [u8; 16],
        sku: String,
        family: String,
    },
    Processor {
        socket_designation: String,
        processor_type: u8,
        processor_family: u8,
        processor_manufacturer: String,
        processor_id: u16,
        processor_version: String,
        voltage: u8,
        external_clock: u16,
        max_speed: u16,
        current_speed: u16,
    },
    MemoryDevice {
        memory_manufacturer: String,
        size: u16,
        memory_speed: u16,
    },
}

impl SMBIOS {
    pub fn new_unchecked(addr: usize) -> Self {
        Self {
            address: addr,
            header: unsafe { (addr as *const SMBIOS32Header).read_volatile() },
        }
    }

    fn parse_string(&self, table_end: usize, nr: usize) -> Option<&str> {
        if nr == 0 {
            return None;
        }

        let mut addr = table_end;
        let mut counter = 1;

        loop {
            let c_str = unsafe { CStr::from_ptr(addr as *const i8) };

            let data = c_str.to_bytes();

            if data.is_empty() {
                return None;
            }

            if counter == nr {
                return Some(c_str.to_str().unwrap());
            }

            addr += data.len() + 1;

            counter += 1;
        }
    }

    pub fn scan(&self) -> Vec<SMBIOSEntry> {
        let mut entries = Vec::new();

        let mut addr = self.header.structure_table_addr;
        let len = self.header.structure_table_length;

        let mut found = 0;

        while addr < (addr + len as u32) {
            if found == self.header.number_of_structs {
                break;
            }

            let header = unsafe { (addr as *const SMBIOSEntryHeader).read() };

            if header.header_type == 127 {
                break;
            }

            if header.length == 0 {
                break;
            }

            let data =
                unsafe { core::slice::from_raw_parts(addr as *const u8, header.length as usize) };

            let mut table_end = addr + header.length as u32;

            match header.header_type {
                // Platform Firmware Information
                0 => {
                    let ven = data[0x4];
                    let fw_ver = data[0x5];
                    let bios_start = ((data[0x7] as u16) << 8) | data[0x6] as u16;
                    let firmware_release_date = data[0x8];
                    let firmware_rom_size = data[0x9];

                    let venstr = self
                        .parse_string(table_end as _, ven as _)
                        .unwrap_or("Unknown");
                    let fw = self
                        .parse_string(table_end as _, fw_ver as _)
                        .unwrap_or("Unknown");
                    let fwrel = self
                        .parse_string(table_end as _, firmware_release_date as _)
                        .unwrap_or("Unknown");

                    entries.push(SMBIOSEntry::BIOS {
                        vendor: venstr.to_owned(),
                        firmware_version: fw.to_owned(),
                        segment_address: bios_start,
                        release_date: fwrel.to_owned(),
                        rom_size: firmware_rom_size as usize,
                    });
                }
                // System Information
                1 => {
                    let manufacturer = data[0x4];
                    let product_name = data[0x5];
                    let version = data[0x6];
                    let serial_number = data[0x7];
                    let uuid: &[u8] = &data[0x8..0x18];
                    let sku = data[0x19];
                    let family = data[0x1A];

                    let manufacturer = self
                        .parse_string(table_end as _, manufacturer as _)
                        .unwrap_or("Unknown");
                    let product_name = self
                        .parse_string(table_end as _, product_name as _)
                        .unwrap_or("Unknown");
                    let version = self
                        .parse_string(table_end as _, version as _)
                        .unwrap_or("Unknown");
                    let serial_number = self
                        .parse_string(table_end as _, serial_number as _)
                        .unwrap_or("Unknown");
                    let sku = self
                        .parse_string(table_end as _, sku as _)
                        .unwrap_or("Unknown");
                    let family = self
                        .parse_string(table_end as _, family as _)
                        .unwrap_or("Unknown");

                    entries.push(SMBIOSEntry::System {
                        manufacturer: manufacturer.to_owned(),
                        product_name: product_name.to_owned(),
                        version: version.to_owned(),
                        serial_number: serial_number.to_owned(),
                        uuid: {
                            let mut n_uuid = [0u8; 16];
                            n_uuid.copy_from_slice(uuid);
                            n_uuid
                        },
                        sku: sku.to_owned(),
                        family: family.to_owned(),
                    });
                }
                // Processor Information
                4 => {
                    let socket_designation = data[0x4];
                    let processor_type = data[0x5];
                    let processor_family = data[0x6];
                    let processor_manufacturer = data[0x7];
                    let processor_id = u16::from_le_bytes(data[0x8..0xA].try_into().unwrap());
                    let processor_version = data[0x10];
                    let voltage = data[0x11];
                    let external_clock = u16::from_le_bytes(data[0x12..0x14].try_into().unwrap());
                    let max_speed = u16::from_le_bytes(data[0x14..0x16].try_into().unwrap());
                    let current_speed = u16::from_le_bytes(data[0x16..0x18].try_into().unwrap());
                    // let status = data[0x18];
                    // let processor_upgrade = data[0x19];

                    let socket_designation = self
                        .parse_string(table_end as _, socket_designation as _)
                        .unwrap_or("Unknown");
                    let processor_manufacturer = self
                        .parse_string(table_end as _, processor_manufacturer as _)
                        .unwrap_or("Unknown");
                    let processor_version = self
                        .parse_string(table_end as _, processor_version as _)
                        .unwrap_or("Unknown");

                    entries.push(SMBIOSEntry::Processor {
                        socket_designation: socket_designation.to_owned(),
                        processor_type,
                        processor_family,
                        processor_manufacturer: processor_manufacturer.to_owned(),
                        processor_id,
                        processor_version: processor_version.to_owned(),
                        voltage,
                        external_clock,
                        max_speed,
                        current_speed,
                    });
                }
                // Memory Device
                17 => {
                    let size = u16::from_le_bytes(data[0xC..=0xD].try_into().unwrap());
                    let memory_speed = u16::from_le_bytes(data[0x15..=0x16].try_into().unwrap());
                    let memory_manufacturer =
                        u16::from_le_bytes(data[0x20..=0x21].try_into().unwrap());

                    let memory_manufacturer = self
                        .parse_string(table_end as _, memory_manufacturer as _)
                        .unwrap_or("Unknown");

                    entries.push(SMBIOSEntry::MemoryDevice {
                        size,
                        memory_speed,
                        memory_manufacturer: memory_manufacturer.to_owned(),
                    });
                }
                _ => (),
            }

            loop {
                let characters = unsafe { (table_end as *const [u8; 2]).read() };

                table_end += 1;

                if characters == [0, 0] {
                    table_end += 1;
                    break;
                }
            }

            addr = table_end;

            found += 1;
        }

        entries
    }
}

pub fn find_smbios() -> Option<SMBIOS> {
    let mut addr = 0x000F0000;

    while addr <= 0x00FFFFF {
        unsafe {
            let data = core::slice::from_raw_parts(addr as *const u8, 4);

            if data == SMBIOS_32_ANCHOR {
                return Some(SMBIOS::new_unchecked(addr));
            }
        }

        addr += 16;
    }

    None
}
