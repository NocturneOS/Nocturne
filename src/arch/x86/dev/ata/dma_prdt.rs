use core::alloc::Layout;

use alloc::{boxed::Box, slice};

use crate::arch;

#[repr(C, packed)]
pub struct PRDTEntry {
    buffer_phys: u32,
    transfer_size: u16,
    flags: u16,
}

pub struct PRDT {
    prdt_virt_addr: Box<[PRDTEntry]>,
    prdt_phys_addr: usize,
}

impl PRDT {
    pub fn new() -> Self {
        debug_assert!(arch::get_page_size().is_multiple_of(size_of::<PRDTEntry>()));

        let entry_count = arch::get_page_size() / size_of::<PRDTEntry>();

        let virt = unsafe {
            slice::from_raw_parts_mut(
                alloc::alloc::alloc_zeroed(
                    Layout::from_size_align(arch::get_page_size(), arch::get_page_size()).unwrap(),
                ) as *mut PRDTEntry,
                entry_count,
            )
        };

        let virt = unsafe { Box::from_raw(virt) };
        let phys = crate::arch::mem::paging::virt2phys(virt.as_ptr().addr()).unwrap();

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

        *self.prdt_virt_addr.get_mut(idx).ok_or(())? = PRDTEntry {
            buffer_phys: physical_addr,
            transfer_size: controller_length,
            flags: if is_last { 0x8000 } else { 0 },
        };

        Ok(())
    }

    pub fn phys(&self) -> u32 {
        self.prdt_phys_addr.try_into().unwrap()
    }
}
