struct Ac97Card {
    busnum: u8,
    slot: u8,
    func: u8,

    nam_addr: u16,
    nabm_addr: u16,

    sample_rate: u16,

    bdl_buffer: Box<[Bdl; 32]>
    lvi: usize
}

impl Ac97Card {
    pub fn set_master_volume(&self, left: u8, right: u8, mute: bool) {
        let val = ((left as u16 & 63) << 0) | (((right as u16) & 63) << 8) | ((mute as u16) << 15);

        x86::io::outw(self.nam_addr + NAM_SET_MASTER_VOLUME, val);
    }

    pub fn set_pcm_volume(&self, left: u8, right: u8, mute: bool) {
        let val = ((left as u16 & 31) << 0) | (((right as u16) & 31) << 8) | ((mute as u16) << 15);

        x86::io::outw(self.nam_addr + NAM_SET_PCM_VOLUME, val);
    }

    pub fn set_sample_rate(&self, sr: u16) {
       x86::io::outw(self.nam_addr + NAM_SAMPLE_RATE, sr); 
    }
}
