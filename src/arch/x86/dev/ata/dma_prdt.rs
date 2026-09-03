use core::alloc::Layout;

use alloc::{boxed::Box, slice};

use crate::arch;

#[repr(C, packed)]
pub struct PrdtEntry {
    buffer_phys: u32,
    transfer_size: u16,
    flags: u16,
}

impl PrdtEntry {
    pub fn buffer_phys(&self) -> u32 {
        self.buffer_phys
    }

    pub fn transfer_size(&self) -> u16 {
        self.transfer_size
    }

    pub fn is_last(&self) -> bool {
        self.flags & 0x8000 != 0
    }
}

pub struct Prdt {
    prdt_virt_addr: Box<[PrdtEntry]>,
    prdt_phys_addr: usize,
}

impl Prdt {
    pub fn new() -> Self {
        debug_assert!(arch::get_page_size().is_multiple_of(size_of::<PrdtEntry>()));

        let entry_count = arch::get_page_size() / size_of::<PrdtEntry>();

        let virt = unsafe {
            slice::from_raw_parts_mut(
                alloc::alloc::alloc_zeroed(
                    Layout::from_size_align(arch::get_page_size(), arch::get_page_size()).unwrap(),
                ) as *mut PrdtEntry,
                entry_count,
            )
        };

        let virt = unsafe { Box::from_raw(virt) };
        let phys = noct_mem::paging::virt2phys(virt.as_ptr().addr()).unwrap();

        Self {
            prdt_virt_addr: virt,
            prdt_phys_addr: phys,
        }
    }

    pub fn clear(&mut self) {
        self.prdt_virt_addr
            .fill_with(|| unsafe { core::mem::zeroed() });
    }

    pub fn set(
        &mut self,
        idx: usize,
        physical_addr: u32,
        length: u16,
        is_last: bool,
    ) -> Result<(), ()> {
        if length == 0 {
            return Err(());
        }

        // 0 is 65535 for ATA controller.
        let controller_length = if length == u16::MAX { 0 } else { length };

        *self.prdt_virt_addr.get_mut(idx).ok_or(())? = PrdtEntry {
            buffer_phys: physical_addr,
            transfer_size: controller_length,
            flags: if is_last { 0x8000 } else { 0 },
        };

        Ok(())
    }

    pub fn get(&self, idx: usize) -> Option<&PrdtEntry> {
        self.prdt_virt_addr.get(idx)
    }

    pub fn phys(&self) -> u32 {
        self.prdt_phys_addr.try_into().unwrap()
    }
}
