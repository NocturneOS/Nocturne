use crate::arch::x86::video::VideoMode;

pub struct Canvas<'vid> {
    video: &'vid mut VideoMode
}

impl<'vid> Canvas<'vid> {
    pub fn new(vid: &'vid mut VideoMode) -> Self {
        Self {
            video: vid
        }
    }

    pub fn fill(&mut self, color: usize) {
        let bpp = self.video.bpp().unwrap();
        let repr = &color.to_le_bytes();

        for chunk in self.video.buffer_mut().chunks_mut(bpp) {
            chunk[..repr.len()].copy_from_slice(repr);
        }

        // self.video.buffer_mut().fill(0xff);
    }
}