#![no_std]

extern crate alloc;

use core::sync::atomic::{AtomicUsize, Ordering};

use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;

pub static AUDIO_DEVICE_GLOBAL_ID: AtomicUsize = AtomicUsize::new(0);
pub static mut AUDIO_DEVICES: Option<Vec<Box<dyn AudioDevice>>> = None;

pub trait AudioDevice {
    fn open(&self);
    fn set_volume(&self, l: u8, r: u8);
    fn set_rate(&self, rate: u32);
    fn write(&self, data: &[u8]);
    fn name(&self) -> &str;
    fn close(&self);
}

pub fn generate_id() -> usize {
    AUDIO_DEVICE_GLOBAL_ID.fetch_add(1, Ordering::AcqRel)
}

#[inline]
#[allow(static_mut_refs)]
pub fn get_device(index: usize) -> Option<&'static dyn AudioDevice> {
    let devs = unsafe { AUDIO_DEVICES.as_mut().expect("Not initialized!") };

    devs.get(index).map(|v| &**v)
}

pub fn init() {
    unsafe {
        AUDIO_DEVICES = Some(vec![]);
    }
}
