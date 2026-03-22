use noct_spec::{KERNEL_BASE, units::Size};

pub mod bios_text_vga;

#[derive(Debug)]
pub enum VideoModeType {
    Text,
    Graphics,
}

#[derive(Debug)]
pub struct VideoMode {
    buffer_ptr: usize,

    resolution: Size<usize>,
    mode_type: VideoModeType,
}

impl VideoMode {
    pub fn buffer(&self) -> *const u8 {
        self.buffer_ptr as *const u8
    }

    pub fn buffer_mut(&self) -> *mut u8 {
        self.buffer_ptr as *mut u8
    }

    pub fn resolution(&self) -> &Size<usize> {
        &self.resolution
    }

    pub fn mode(&self) -> &VideoModeType {
        &self.mode_type
    }
}

use lazy_static::lazy_static;
use spin::Mutex;

lazy_static! {
    static ref CURRENT_VIDEO_MODE: Mutex<VideoMode> = VideoMode {
        buffer_ptr: 0xB8000 + KERNEL_BASE,
        resolution: Size::<usize> {
            width: 80,
            height: 25,
        },
        mode_type: VideoModeType::Text
    }
    .into();
}
