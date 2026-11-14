#![no_std]

use alloc::boxed::Box;

extern crate alloc;

const NAM_RESET: u16 =  0x00;
const NAM_SET_MASTER_VOLUME: u16 =  0x02;
const NAM_SET_PCM_VOLUME: u16 =  0x18;
const NAM_EXTENDED_ID: u16 =  0x28;
const NAM_EXTENDED_AUDIO: u16 =  0x2A;
const NAM_SAMPLE_RATE: u16 =  0x2C;

const NABM_PCM_OUT: u16 =  0x10;
const NABM_GLOBAL_CONTROL: u16 =  0x2C;
const NABM_GLOBAL_STATUS : u16 =  0x30;

struct Ac97Card {
    busnum: u8,
    slot: u8,
    func: u8,

    nam_addr: u16,
    nabm_addr: u16,

    sample_rate: u16,

    bdl_buffer: Box<[Bdl; 32]>,
    lvi: usize
}

#[repr(C, packed)]
struct Bdl {

}

impl Ac97Card {
    pub fn set_master_volume(&self, left: u8, right: u8, mute: bool) {
        let val = ((left as u16 & 63) << 0) | (((right as u16) & 63) << 8) | ((mute as u16) << 15);

        unsafe { x86::io::outw(self.nam_addr + NAM_SET_MASTER_VOLUME, val) };
    }

    pub fn set_pcm_volume(&self, left: u8, right: u8, mute: bool) {
        let val = ((left as u16 & 31) << 0) | (((right as u16) & 31) << 8) | ((mute as u16) << 15);

        unsafe { x86::io::outw(self.nam_addr + NAM_SET_PCM_VOLUME, val) };
    }

    pub fn set_sample_rate(&self, sr: u16) {
       unsafe { x86::io::outw(self.nam_addr + NAM_SAMPLE_RATE, sr) }; 
    }
}
