pub struct IOPort(u16);

impl IOPort {
	pub fn offset(&self, offset: u16) -> Self {
		Self(self.0 + offset)
	}

	pub fn write8(&self, value: u8) {
		unsafe { x86::io::outb(self.0, value) };
	}

	pub fn write16(&self, value: u16) {
		unsafe { x86::io::outw(self.0, value) };
	}

	pub fn write32(&self, value: u32) {
		unsafe { x86::io::outl(self.0, value) };
	}

	pub fn read8(&self) -> u8 {
	    unsafe { x86::io::inb(self.0) }
	}
	
	pub fn read16(&self) -> u16 {
	    unsafe { x86::io::inw(self.0) }
	}
	
	pub fn read32(&self, value: u32) -> u32 {
	    unsafe { x86::io::inl(self.0) }
	}
}
