pub mod clone;

use bitflags::bitflags;

bitflags! {
    #[derive(Copy, Clone)]
    pub struct PageFlags : usize {
        const Present = 1 << 0;
        const Writeable = 1 << 1;
        const Userspace = 1 << 2;
        const WriteThrough = 1 << 3;
        const CacheDisable = 1 << 4;
        const Accessed = 1 << 5;
        const Dirty = 1 << 6;
        const Extended = 1 << 7;
        const Global = 1 << 8;
    }
}

impl PageFlags {
    pub fn with_pat(mut self, pat: u8) -> Self {
        let low = pat & 0b1;
        let mid = pat & (0b10);
        let hi = pat & (0b100);

        if low != 0 {
            self |= Self::WriteThrough;
        }

        if mid != 0 {
            self |= Self::CacheDisable;
        }

        // WARNING: Using bit 2 in PAT while working with PDE (Page Directory Entry) is dangerous!
        if hi != 0 {
            self |= Self::Extended;
        }

        self
    }
}

#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, PartialOrd)]
pub struct Page(pub usize);

impl Page {
    pub fn new(phys_addr: usize, flags: PageFlags) -> Self {
        Self(phys_addr | flags.bits())
    }

    pub fn null() -> Self {
        Self(0)
    }

    pub fn raw(&self) -> usize {
        self.0
    }

    pub fn phys(&self) -> usize {
        self.0 & !0xfff
    }

    pub fn flags(&self) -> PageFlags {
        PageFlags::from_bits(self.0 & 0x1FF).unwrap()
    }

    pub fn set_flags(&mut self, flags: PageFlags) {
        self.0 = (self.0 & !0x1FF) | flags.bits();
    }

    pub fn is_present(&self) -> bool {
        self.flags().contains(PageFlags::Present)
    }

    pub fn is_writeable(&self) -> bool {
        self.flags().contains(PageFlags::Writeable)
    }

    pub fn is_extended(&self) -> bool {
        self.flags().contains(PageFlags::Extended)
    }

    pub fn is_usermode(&self) -> bool {
        self.flags().contains(PageFlags::Userspace)
    }

    pub fn set_usermode(&mut self, usermode: bool) {
        if usermode {
            self.0 |= PageFlags::Userspace.bits();
        } else {
            self.0 &= !PageFlags::Userspace.bits();
        }
    }
}

impl PartialEq<usize> for Page {
    fn eq(&self, other: &usize) -> bool {
        self.0 == *other
    }
}
