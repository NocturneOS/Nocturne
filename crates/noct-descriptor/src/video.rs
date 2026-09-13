type VideoLock = spin::mutex::MutexGuard<'static, Option<noct_video::VideoMode>>;

pub struct VideoHandle {
    lock: VideoLock,

    offset: usize,
}

impl core::fmt::Debug for VideoHandle {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("VideoHandle").finish()
    }
}

impl VideoHandle {
    pub fn from_lock(lock: VideoLock) -> Self {
        Self { lock, offset: 0 }
    }

    pub fn buffer_len(&self) -> usize {
        self.lock.as_ref().unwrap().buffer_size()
    }

    pub fn seek(&mut self, offset: usize) {
        self.offset = offset;
    }

    pub fn offset(&self) -> usize {
        self.offset
    }

    pub fn write(&mut self, data: &[u8]) -> usize {
        let mut write_size: usize = 0;

        let buffer = self
            .lock
            .as_mut()
            .unwrap()
            .buffer_mut()
            .get_mut(self.offset..)
            .and_then(|x| {
                write_size = core::cmp::min(data.len(), x.len());

                x.get_mut(..write_size)
            });

        if let Some(buf) = buffer {
            buf.copy_from_slice(&data[..write_size]);

            self.offset += data.len();
        }

        write_size
    }
}
