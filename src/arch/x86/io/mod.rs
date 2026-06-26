pub struct IOPort(u16);

impl IOPort {
    pub fn new(port: u16) -> Self {
        Self(port)
    }

    pub fn addr(&self) -> u16 {
        self.0
    }

    pub fn offset(&self, offset: u16) -> Self {
        Self(self.0 + offset)
    }

    pub unsafe fn write8(&self, value: u8) {
        unsafe { x86::io::outb(self.0, value) };
    }

    pub unsafe fn write16(&self, value: u16) {
        unsafe { x86::io::outw(self.0, value) };
    }

    pub unsafe fn write16_bulk(&self, values: &[u16]) {
        for value in values {
            unsafe { x86::io::outw(self.0, *value) };
        }
    }

    pub unsafe fn write32(&self, value: u32) {
        unsafe { x86::io::outl(self.0, value) };
    }

    pub unsafe fn read8(&self) -> u8 {
        unsafe { x86::io::inb(self.0) }
    }

    pub unsafe fn read16(&self) -> u16 {
        unsafe { x86::io::inw(self.0) }
    }

    pub unsafe fn read16_bulk(&self, out: &mut [u16]) {
        for value in out.iter_mut() {
            *value = unsafe { x86::io::inw(self.0) }
        }
    }

    pub unsafe fn read32(&self) -> u32 {
        unsafe { x86::io::inl(self.0) }
    }
}
