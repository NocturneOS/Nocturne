//! AC'97 audio driver (Intel 82801 / 8086:2415).

#![no_std]

extern crate alloc;

mod bdl;
mod dma;

use core::{
    ops::RangeInclusive,
    sync::atomic::{AtomicBool, AtomicU16, Ordering},
};

use alloc::boxed::Box;
use noct_audio::AudioDevice;
use noct_ioport::IOPort;
use noct_logger::qemu_log;
use noct_pci::{bar::BARType, device::PCIDevice};

use crate::{
    bdl::{BDL_FLAG_BUP, BDL_FLAG_IOC, Bdl},
    dma::DmaAllocation,
};

const VENDOR: u16 = 0x8086;
const DEVICE: u16 = 0x2415;

const RATE: RangeInclusive<u16> = 8000..=48000;
const DEFAULT_RATE: u16 = 48000;
const VARIABLE_RATE_DEFAULT: u16 = 44100;

const NAM_RESET: u16 = 0x00;
const NAM_SET_MASTER_VOLUME: u16 = 0x02;
const NAM_SET_PCM_VOLUME: u16 = 0x18;
const NAM_EXTENDED_ID: u16 = 0x28;
const NAM_EXTENDED_AUDIO: u16 = 0x2A;
const NAM_SAMPLE_RATE: u16 = 0x2C;

const NABM_GLOBAL_CONTROL: u16 = 0x2C;
const NABM_GLOBAL_STATUS: u16 = 0x30;

const NABM_GLOBAL_CONTROL_COLD_RESET: u32 = 1 << 1;
const NABM_GLOBAL_STATUS_PRIMARY_CODEC_READY: u32 = 1 << 8;

const NABM_PCM_OUT_BDBAR: u16 = 0x10;
const NABM_PCM_OUT_LVI: u16 = 0x15;
const NABM_PCM_OUT_SR: u16 = 0x16;
const NABM_PCM_OUT_CR: u16 = 0x1B;

const SR_DCH: u8 = 1 << 0;
const SR_BCIS: u8 = 1 << 3;
const SR_CLEAR: u8 = (1 << 2) | (1 << 3) | (1 << 4);

const CR_RPBM: u8 = 1 << 0;
const CR_RR: u8 = 1 << 1;

const BDLS_COUNT: usize = 32;
const AUDIO_BUFFER_SIZE: usize = 128 * 1024;

// Every BDL entry spans exactly one page, so its physical address can be
// resolved without relying on physically contiguous heap pages.
const BDL_ENTRY_SIZE: usize = AUDIO_BUFFER_SIZE / BDLS_COUNT;

// AC'97 is 16-bit stereo here, and the BDL length is counted in 16-bit samples.
const BDL_ENTRY_SAMPLES: u16 = (BDL_ENTRY_SIZE / 2) as u16;

const RESET_TIMEOUT_MS: u128 = 100;
const CODEC_READY_TIMEOUT_MS: u128 = 1_000;
const PLAYBACK_EXTRA_TIMEOUT_MS: u128 = 1_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ac97Error {
    DeviceNotFound,
    MissingBar(u8),
    BarIsNotIo(u8),
    BufferAllocationFailed,
    BufferNotMapped,
    AddressOutOfRange,
    ResetTimeout,
    PlaybackTimeout,
    VariableRateUnsupported,
    InvalidSampleRate(u32),
}

pub struct Ac97Card {
    _device: PCIDevice,

    nam: IOPort,
    nabm: IOPort,

    variable_rate: bool,

    bdl: DmaAllocation,
    buffer: DmaAllocation,

    sample_rate: AtomicU16,
    busy: AtomicBool,
}

impl Ac97Card {
    pub fn new() -> Result<Self, Ac97Error> {
        let device = noct_pci::find_device(VENDOR, DEVICE).ok_or(Ac97Error::DeviceNotFound)?;

        qemu_log!("Found AC'97 audio device");

        device.enable_bus_mastering();

        let nam_bar = device.read_bar(0).ok_or(Ac97Error::MissingBar(0))?;
        let nabm_bar = device.read_bar(1).ok_or(Ac97Error::MissingBar(1))?;

        if nam_bar.bar_type != BARType::IO {
            return Err(Ac97Error::BarIsNotIo(0));
        }

        if nabm_bar.bar_type != BARType::IO {
            return Err(Ac97Error::BarIsNotIo(1));
        }

        let nam = IOPort::new(nam_bar.address as u16);
        let nabm = IOPort::new(nabm_bar.address as u16);

        qemu_log!("NAM: {:#06x}; NABM: {:#06x}", nam.addr(), nabm.addr());

        let extended_id = unsafe { nam.offset(NAM_EXTENDED_ID).read16() };

        // Get revision.
        {
            let revision = ((extended_id >> 10) & 0b11) as usize;
            let revisions = ["r < 21", "r22", "r23", "unknown"];

            qemu_log!("Codec revision: ({revision}) {}", revisions[revision]);
        }

        // Cold reset.
        {
            let global_control = nabm.offset(NABM_GLOBAL_CONTROL);
            let gc = unsafe { global_control.read32() };

            qemu_log!("Received global control: ({gc}) {gc:#010x}");

            unsafe { global_control.write32(gc | NABM_GLOBAL_CONTROL_COLD_RESET) };
        }

        if !wait_for_codec_ready(&nabm) {
            qemu_log!("AC'97: primary codec did not become ready after cold reset");
        }

        // Reset the codec itself.
        {
            let reset = nam.offset(NAM_RESET);

            unsafe { reset.write16(1) };

            let start = uptime_millis();

            while (unsafe { reset.read16() } & 1) != 0 {
                if timed_out(start, CODEC_READY_TIMEOUT_MS) {
                    qemu_log!("AC'97: codec reset did not complete in time");
                    break;
                }

                noct_sched::yield_now();
            }
        }

        if !wait_for_codec_ready(&nabm) {
            qemu_log!("AC'97: primary codec is not ready after reset");
        }

        let variable_rate = (extended_id & 1) != 0;

        // Enable variable sample rate if the codec supports it.
        {
            let extended_audio_port = nam.offset(NAM_EXTENDED_AUDIO);
            let mut extended_audio = unsafe { extended_audio_port.read16() };

            if variable_rate {
                qemu_log!("AC'97 supports variable sample rate");
                extended_audio |= 1;
            }

            unsafe { extended_audio_port.write16(extended_audio) };
        }

        let page_size = noct_mem::get_page_size();

        let bdl =
            DmaAllocation::zeroed(page_size, page_size).ok_or(Ac97Error::BufferAllocationFailed)?;
        let buffer = DmaAllocation::zeroed(AUDIO_BUFFER_SIZE, page_size)
            .ok_or(Ac97Error::BufferAllocationFailed)?;

        let card = Self {
            _device: device,
            nam,
            nabm,
            variable_rate,
            bdl,
            buffer,
            sample_rate: AtomicU16::new(if variable_rate {
                VARIABLE_RATE_DEFAULT
            } else {
                DEFAULT_RATE
            }),
            busy: AtomicBool::new(false),
        };

        card.fill_bdls()?;
        card.mark_bdl(BDLS_COUNT - 1);

        card.stop();
        card.reset_channel()?;
        card.clear_status();
        card.set_bdl_base()?;
        card.set_lvi((BDLS_COUNT - 1) as u8);

        card.set_master_volume(0, 0, false);
        card.set_pcm_volume(0, 0, false);

        if variable_rate {
            card.set_sample_rate(VARIABLE_RATE_DEFAULT)?;
        }

        qemu_log!("AC'97 capabilities updated");

        Ok(card)
    }

    pub fn is_variable_rate(&self) -> bool {
        self.variable_rate
    }

    pub fn sample_rate(&self) -> u16 {
        self.sample_rate.load(Ordering::Relaxed)
    }

    /// Volume is in dB, not percent (max 64).
    pub fn set_master_volume(&self, left: u8, right: u8, mute: bool) {
        let value = ((mute as u16) << 15) | (((left & 63) as u16) << 8) | ((right & 63) as u16);

        unsafe { self.nam.offset(NAM_SET_MASTER_VOLUME).write16(value) };
    }

    /// Volume is in dB, not percent (max 32).
    pub fn set_pcm_volume(&self, left: u8, right: u8, mute: bool) {
        let value = ((mute as u16) << 15) | (((left & 31) as u16) << 8) | ((right & 31) as u16);

        unsafe { self.nam.offset(NAM_SET_PCM_VOLUME).write16(value) };
    }

    pub fn set_sample_rate(&self, sample_rate: u16) -> Result<(), Ac97Error> {
        if !self.variable_rate {
            return Err(Ac97Error::VariableRateUnsupported);
        }

        if !RATE.contains(&sample_rate) {
            return Err(Ac97Error::InvalidSampleRate(sample_rate as u32));
        }

        unsafe { self.nam.offset(NAM_SAMPLE_RATE).write16(sample_rate) };

        self.sample_rate.store(sample_rate, Ordering::Relaxed);

        Ok(())
    }

    fn fill_bdls(&self) -> Result<(), Ac97Error> {
        let bdl = self.bdl.ptr().cast::<Bdl>();

        for i in 0..BDLS_COUNT {
            let phys = self
                .buffer
                .phys_at(i * BDL_ENTRY_SIZE)
                .ok_or(Ac97Error::BufferNotMapped)?;
            let phys = u32::try_from(phys).map_err(|_| Ac97Error::AddressOutOfRange)?;

            let flags = if i + 1 == BDLS_COUNT {
                BDL_FLAG_IOC | BDL_FLAG_BUP
            } else {
                0
            };

            unsafe { bdl.add(i).write(Bdl::new(phys, BDL_ENTRY_SAMPLES, flags)) };
        }

        Ok(())
    }

    /// Mark `last` as the final valid descriptor for the next transfer.
    fn mark_bdl(&self, last: usize) {
        let bdl = self.bdl.ptr().cast::<Bdl>();

        for i in 0..BDLS_COUNT {
            // Do interrupt and stop playback when the BDL entry hits.
            let flags = if i == last {
                BDL_FLAG_IOC | BDL_FLAG_BUP
            } else {
                0
            };

            unsafe {
                let mut entry = bdl.add(i).read();

                entry = Bdl::new(entry.memory_pos(), entry.sample_count(), flags);
                bdl.add(i).write(entry);
            }
        }
    }

    fn set_bdl_base(&self) -> Result<(), Ac97Error> {
        let phys = self.bdl.phys_at(0).ok_or(Ac97Error::BufferNotMapped)?;
        let phys = u32::try_from(phys).map_err(|_| Ac97Error::AddressOutOfRange)?;

        unsafe { self.nabm.offset(NABM_PCM_OUT_BDBAR).write32(phys) };

        Ok(())
    }

    fn set_lvi(&self, index: u8) {
        unsafe { self.nabm.offset(NABM_PCM_OUT_LVI).write8(index & 0b11111) };
    }

    fn status(&self) -> u8 {
        unsafe { self.nabm.offset(NABM_PCM_OUT_SR).read8() }
    }

    fn clear_status(&self) {
        unsafe { self.nabm.offset(NABM_PCM_OUT_SR).write8(SR_CLEAR) };
    }

    fn set_playing(&self, playing: bool) {
        let control = self.nabm.offset(NABM_PCM_OUT_CR);
        let mut value = unsafe { control.read8() };

        if playing {
            value |= CR_RPBM;
        } else {
            value &= !CR_RPBM;
        }

        unsafe { control.write8(value) };
    }

    fn reset_channel(&self) -> Result<(), Ac97Error> {
        let control = self.nabm.offset(NABM_PCM_OUT_CR);

        unsafe { control.write8(CR_RR) };

        let start = uptime_millis();

        while (unsafe { control.read8() } & CR_RR) != 0 {
            if timed_out(start, RESET_TIMEOUT_MS) {
                return Err(Ac97Error::ResetTimeout);
            }

            noct_sched::yield_now();
        }

        Ok(())
    }

    fn stop(&self) {
        self.set_playing(false);

        let start = uptime_millis();

        while (self.status() & SR_DCH) == 0 {
            if timed_out(start, RESET_TIMEOUT_MS) {
                break;
            }

            noct_sched::yield_now();
        }
    }

    fn wait_for_completion(&self, block_len: usize) -> Result<(), Ac97Error> {
        let rate = self.sample_rate().max(1) as u64;

        // 16-bit stereo: 4 bytes per frame.
        let expected_ms = (block_len as u64).saturating_mul(1000) / (rate * 4);
        let timeout_ms = expected_ms as u128 + PLAYBACK_EXTRA_TIMEOUT_MS;

        let start = uptime_millis();

        loop {
            if (self.status() & SR_BCIS) != 0 {
                return Ok(());
            }

            if timed_out(start, timeout_ms) {
                qemu_log!("AC'97: playback completion timed out");

                return Err(Ac97Error::PlaybackTimeout);
            }

            noct_sched::yield_now();
        }
    }

    fn play_block(&self, data: &[u8]) -> Result<(), Ac97Error> {
        if data.is_empty() {
            return Ok(());
        }

        let block_len = data.len().min(AUDIO_BUFFER_SIZE);
        let entries = block_len.div_ceil(BDL_ENTRY_SIZE).clamp(1, BDLS_COUNT);
        let last = entries - 1;

        unsafe {
            core::ptr::copy_nonoverlapping(data.as_ptr(), self.buffer.ptr(), block_len);

            // Zero out the remaining space so that a partial last descriptor
            // plays silence instead of stale samples.
            if block_len < AUDIO_BUFFER_SIZE {
                core::ptr::write_bytes(
                    self.buffer.ptr().add(block_len),
                    0,
                    AUDIO_BUFFER_SIZE - block_len,
                );
            }
        }

        self.mark_bdl(last);

        self.stop();
        self.reset_channel()?;
        self.clear_status();

        self.set_bdl_base()?;
        self.set_lvi(last as u8);
        self.set_playing(true);

        self.wait_for_completion(block_len)?;

        self.stop();

        Ok(())
    }

    fn playback(&self, data: &[u8]) -> Result<(), Ac97Error> {
        if data.is_empty() {
            return Ok(());
        }

        let _guard = self.acquire_playback();

        let mut loaded = 0;

        // Play the buffer block by block (block size matches audio buffer size)
        while loaded < data.len() {
            let end = (loaded + AUDIO_BUFFER_SIZE).min(data.len());

            self.play_block(&data[loaded..end])?;

            loaded = end;
        }

        Ok(())
    }

    fn acquire_playback(&self) -> PlaybackGuard<'_> {
        while self
            .busy
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            noct_sched::yield_now();
        }

        PlaybackGuard(&self.busy)
    }
}

impl AudioDevice for Ac97Card {
    fn open(&self) {
        qemu_log!("AC'97: opened");

        self.clear_status();
    }

    /// Volume is in range 0 - 100.
    fn set_volume(&self, left: u8, right: u8) {
        let left = left.min(100) as u32;
        let right = right.min(100) as u32;

        let left_master = ((100 - left) * 63 / 100) as u8;
        let right_master = ((100 - right) * 63 / 100) as u8;
        let left_pcm = ((100 - left) * 31 / 100) as u8;
        let right_pcm = ((100 - right) * 31 / 100) as u8;

        self.set_master_volume(left_master, right_master, false);
        self.set_pcm_volume(left_pcm, right_pcm, false);
    }

    fn set_rate(&self, rate: u32) {
        let Ok(rate) = u16::try_from(rate) else {
            qemu_log!("AC'97: invalid sample rate {rate}");
            return;
        };

        match self.set_sample_rate(rate) {
            Ok(()) => {
                qemu_log!("AC'97: sample rate set to {rate} Hz");
            }
            Err(error) => {
                qemu_log!("AC'97: cannot set sample rate {rate}: {error:?}");
            }
        }
    }

    fn write(&self, data: &[u8]) {
        if let Err(error) = self.playback(data) {
            qemu_log!("AC'97: playback failed: {error:?}");
        }
    }

    fn name(&self) -> &str {
        "AC'97"
    }

    fn close(&self) {
        qemu_log!("AC'97: closed");

        let _guard = self.acquire_playback();

        self.stop();
        let _ = self.reset_channel();
        self.clear_status();
    }
}

struct PlaybackGuard<'a>(&'a AtomicBool);

impl Drop for PlaybackGuard<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

pub fn init() -> Result<(), Ac97Error> {
    let card = Ac97Card::new()?;

    //card.set_volume(100, 100);
    //card.set_sample_rate(44100).expect("Failed to set sample rate");

    let id = noct_audio::register_device(Box::new(card));

    qemu_log!("AC'97 initialized successfully (audio device #{id})");

    Ok(())
}

fn uptime_millis() -> u128 {
    noct_time::systemclock::get_uptime_millis()
}

fn timed_out(start: u128, timeout_ms: u128) -> bool {
    uptime_millis().saturating_sub(start) > timeout_ms
}

fn wait_for_codec_ready(nabm: &IOPort) -> bool {
    let status = nabm.offset(NABM_GLOBAL_STATUS);

    let start = uptime_millis();

    loop {
        if (unsafe { status.read32() } & NABM_GLOBAL_STATUS_PRIMARY_CODEC_READY) != 0 {
            return true;
        }

        if timed_out(start, CODEC_READY_TIMEOUT_MS) {
            return false;
        }

        noct_sched::yield_now();
    }
}
