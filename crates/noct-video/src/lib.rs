#![no_std]

pub mod canvas;
pub mod video_mode;
pub mod color_layout;

use lazy_static::lazy_static;
use spin::Mutex;

pub use crate::video_mode::VideoMode;

lazy_static! {
    pub static ref CURRENT_VIDEO_MODE: Mutex<Option<VideoMode>> = None.into();
}
