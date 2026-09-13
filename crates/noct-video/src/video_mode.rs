use noct_spec::units::Size;

#[derive(Debug)]
pub enum VideoModeType {
    Text,     // Not yet used
    Graphics {
        /// In bytes
        bpp: usize
    },
}

#[derive(Debug)]
pub struct VideoMode {
    buffer_physical_addr: usize,
    buffer_ptr: usize,

    resolution: Size<usize>,
    mode: VideoModeType,
}

impl VideoMode {
    pub fn new_graphics(fb: *mut u8, phys_addr: usize, size: Size<usize>, bpp: usize) -> Self {
        VideoMode {
            buffer_ptr: fb.addr(),
            buffer_physical_addr: phys_addr,
            resolution: size,
            mode: VideoModeType::Graphics { bpp },
        }
    }

    pub fn as_ptr(&self) -> *const u8 {
        self.buffer_ptr as *const u8
    }

    pub fn as_mut_ptr(&self) -> *mut u8 {
        self.buffer_ptr as *mut u8
    }

    pub fn buffer(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self.as_ptr(), self.resolution.width * self.resolution.height * self.bpp().unwrap_or(2)) }
    }

    pub fn buffer_mut(&mut self) -> &mut [u8] {
        unsafe { core::slice::from_raw_parts_mut(self.as_mut_ptr(), self.resolution.width * self.resolution.height * self.bpp().unwrap_or(2)) }
    }

    pub fn buffer_phys(&self) -> usize {
        self.buffer_physical_addr
    }

    pub fn resolution(&self) -> &Size<usize> {
        &self.resolution
    }

    pub fn bpp(&self) -> Option<usize> {
        if let VideoModeType::Graphics { bpp } = &self.mode {
            Some(*bpp)
        } else {
            None
        }
    }

    pub fn buffer_size(&self) -> usize {
        let mo = if let VideoModeType::Graphics { bpp } = &self.mode {
            *bpp
        } else {
            2  // For text mode each character takes 2 bytes - one character itself, another its attributes.
        };

        self.resolution.width * self.resolution.height * mo
    }

    pub fn mode(&self) -> &VideoModeType {
        &self.mode
    }
}