#![no_std]

use alloc::vec::Vec;

extern crate alloc;

#[derive(Debug, Clone, Copy)]
pub struct CHS {
    pub cylinders: usize,
    pub heads: usize,
    pub sectors: usize,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PartitionType {
    Free = 0x00,
    NTFS = 0x07,
    Extended = 0x05,
    ExtendedLBA = 0x0F,
    Linux = 0x83,
    LinuxSwap = 0x82,
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct PartitionRecord {
    pub activity: u8,

    pub start_head: u8,
    pub start_sector_cylinder: u16,

    pub partition_type: PartitionType,

    pub end_head: u8,
    pub end_sector_cylinder: u16,

    pub start_sector_lba: u32,
    pub num_sectors: u32,
}

impl PartitionRecord {
    pub fn start_chs(&self) -> CHS {
        let head = self.start_head;
        let sector = self.start_sector_cylinder & 0b111111;
        let cylinder = self.start_sector_cylinder >> 6;

        CHS {
            cylinders: cylinder as _,
            heads: head as _,
            sectors: sector as _,
        }
    }

    pub fn end_chs(&self) -> CHS {
        let head = self.end_head;
        let sector = self.end_sector_cylinder & 0b111111;
        let cylinder = self.end_sector_cylinder >> 6;

        CHS {
            cylinders: cylinder as _,
            heads: head as _,
            sectors: sector as _,
        }
    }
}

pub fn parse_from_sector(data: &[u8]) -> Vec<PartitionRecord> {
    let signature: [u8; 2] = data[510..].try_into().unwrap();

    let mut records = Vec::with_capacity(4);

    if signature != [0x55, 0xaa] {
        return records;
    }

    for i in data[446..510].chunks(size_of::<PartitionRecord>()) {
        let entry: PartitionRecord =
            unsafe { (i.as_ptr() as *const PartitionRecord).read_unaligned() };

        records.push(entry);
    }

    records
}
