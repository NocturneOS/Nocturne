#![no_std]

use core::ops::RangeInclusive;

use alloc::boxed::Box;
use noct_ioport::IOPort;
use noct_logger::qemu_log;
use noct_pci::device::PCIDevice;

use crate::bdl::Bdl;

mod bdl;

extern crate alloc;

const VENDOR: u16 = 0x8086;
const DEVICE: u16 = 0x2415;

const RATE: RangeInclusive<u16> = 8000..=48000;

const NAM_RESET: u16 = 0x00;
const NAM_SET_MASTER_VOLUME: u16 = 0x02;
const NAM_SET_PCM_VOLUME: u16 = 0x18;
const NAM_EXTENDED_ID: u16 = 0x28;
const NAM_EXTENDED_AUDIO: u16 = 0x2A;
const NAM_SAMPLE_RATE: u16 = 0x2C;

const NABM_PCM_OUT: u16 = 0x10;
const NABM_GLOBAL_CONTROL: u16 = 0x2C;
const NABM_GLOBAL_STATUS: u16 = 0x30;

struct Ac97Card {
    device: PCIDevice,

    nam: IOPort,
    nabm: IOPort,

    sample_rate: u16,

    bdl_buffer: Box<[Bdl; 32]>,
    lvi: usize,

    extended_id: usize,
}

impl Ac97Card {
    pub fn new() -> Option<Self> {
        let dev = noct_pci::find_device(VENDOR, DEVICE)?;

        qemu_log!("Found AC'97!");

        dev.enable_bus_mastering();

        let nam = dev.read_bar(0)?;
        let nabm = dev.read_bar(1)?;

        let nam = IOPort::new(nam.address as u16);
        let nabm = IOPort::new(nabm.address as u16);

        // TODO: NAM and NABM into IOPort!

        qemu_log!("Examined NAM and NABM!");

        qemu_log!("NAM: {nam:x?}");
        qemu_log!("NABM: {nabm:x?}");

        let id = unsafe { nam.offset(NAM_EXTENDED_ID).read16() };

        // Get revision
        {
            let revisions = ["r < 21", "r22", "r23"];

            qemu_log!("Revision: {:?}", revisions[(extended_id >> 10) & 0b11]);
        }

        // Cold reset
        {
            let global_control = nabm.offset(NABM_GLOBAL_CONTROL);

            let gc = unsafe { global_control.read32() };

            // Cold reset.
            unsafe { global_control.write32(gc | (1 << 1)) };

            unsafe { nam.offset(NAM_RESET).write16(1) };
        }

        {
            let extended_audio_flags = nam.offset(NAM_EXTENDED_AUDIO);

            let mut xaf = unsafe { extended_audio_flags.read16() };

            // Variable sample rate.
            if (id & 1) != 0 {
                xaf |= 1;
            }

            unsafe { extended_audio_flags.write16(xaf) };
        }

        // TODO: Setup sample rate
        // TODO: Setup volume
        // TODO: Make audio buffer and fill BDLs

        Some(Self {
            device: dev,
            nam,
            nabm,
            sample_rate: todo!(),
            bdl_buffer: todo!(),
            lvi: todo!(),
            extended_id: todo!(),
        })
    }

    pub fn set_master_volume(&self, left: u8, right: u8, mute: bool) {
        let val = ((left as u16 & 63) << 0) | (((right as u16) & 63) << 8) | ((mute as u16) << 15);

        unsafe { self.nam.offset(NAM_SET_MASTER_VOLUME).write16(val) };
    }

    pub fn set_pcm_volume(&self, left: u8, right: u8, mute: bool) {
        let val = ((left as u16 & 31) << 0) | (((right as u16) & 31) << 8) | ((mute as u16) << 15);

        unsafe { self.nam.offset(NAM_SET_PCM_VOLUME).write16(val) };
    }

    pub fn set_sample_rate(&self, sr: u16) {
        if !RATE.contains(&sr) {
            return;
        }

        unsafe { self.nam.offset(NAM_SAMPLE_RATE).write16(sr) };
    }

    pub fn reset_channel(&self) {
        let flags = self.nabm.offset(0x1b);

        unsafe { self.nabm.write8(self.nabm.read8() | 0x02) };

        while unsafe { self.nabm.read8() & 0x02 } != 0 {
            // ...
        }
    }

    fn clear_status(&self) {
        unsafe { self.nabm.offset(0x16).write8(0x1c) };
    }

    fn update_bdl_to_addr(&self, addr: u32) {
        unsafe { self.nabm.offset(NABM_PCM_OUT).write32(addr) };
    }

    fn update_lvi(&self, index: u8) {
        unsafe { self.nabm.offset(NABM_PCM_OUT + 0x05).write8(index & 0b11111) };
    }

    fn set_playing(&self, playing: bool) {
        let flags_port = self.nabm.offset(0x1b);

        let mut flags = unsafe { flags_port.read8() };

        if playing {
            flags |= 0x01;
        } else {
            flags &= !0x01;
        }

        unsafe { flags_port.write8(flags) };
    }
}
