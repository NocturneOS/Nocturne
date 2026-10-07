use crate::video_mode::VideoMode;

pub struct Canvas<'vid> {
    video: &'vid mut VideoMode
}

impl<'vid> Canvas<'vid> {
    pub fn new(vid: &'vid mut VideoMode) -> Self {
        Self {
            video: vid
        }
    }

    pub fn fill(&mut self, color: u32) {
        let bpp = self.video.bpp().unwrap();
        let repr = &color.to_le_bytes();

        for chunk in self.video.buffer_mut().chunks_mut(bpp) {
            chunk[..repr.len()].copy_from_slice(repr);
        }
    }

    pub fn put_pixel(&mut self, x: usize, y: usize, color: u32) -> bool {
        if x >= self.video.resolution().width || y >= self.video.resolution().height {
            return false;
        }
        
        let bpp = self.video.bpp().unwrap();
        let repr = &color.to_le_bytes();

        let offset = ((y * self.video.resolution().width) + x) * self.video.bpp().unwrap();

        self.video.buffer_mut()[offset..][..repr.len()].copy_from_slice(repr);

        true
    }
}