use alloc::{boxed::Box, vec::Vec};

pub struct ATADriveInfo {
    identity: Box<[u8]>,
}

impl ATADriveInfo {
    pub fn raw(&self) -> &[u8] {
        &*self.identity
    }

    pub fn nth_word(&self, word_offset: usize) -> u16 {
        let low = self.identity[(word_offset * 2) + 1] as u16;
        let high = self.identity[word_offset * 2] as u16;

        (high << 8) | low
    }

    // Offset in bytes
    fn name_conv(&self, offset: usize, length: usize) -> &str {
        unsafe { str::from_utf8_unchecked(&self.identity[offset..offset + length]).trim() }
    }

    #[inline]
    pub fn model_name(&self) -> &str {
        self.name_conv(54, 40)
    }

    #[inline]
    pub fn firmware(&self) -> &str {
        self.name_conv(46, 8)
    }

    #[inline]
    pub fn serial(&self) -> &str {
        self.name_conv(20, 20)
    }

    pub fn is_lba_supported(&self) -> bool {
        (self.nth_word(49) & (1 << 9)) != 0
    }

    pub fn is_dma_supported(&self) -> bool {
        (self.nth_word(49) & (1 << 8)) != 0
    }

    pub fn max_lba(&self) -> u64 {
        let word1 = self.nth_word(100) as u64;
        let word2 = self.nth_word(101) as u64;
        let word3 = self.nth_word(102) as u64;
        let word4 = self.nth_word(103) as u64;

        (word4 << 48) | (word3 << 32) | (word2 << 16) | word1
    }

    pub fn is_removable_media_device(&self) -> bool {
        (self.nth_word(0) & (1 << 7)) != 0
    }

    pub fn sector_size(&self) -> usize {
        if self.is_removable_media_device() {
            2048
        } else {
            512
        }
    }
}

impl TryFrom<Vec<u8>> for ATADriveInfo {
    type Error = ();

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        if value.len() != 512 {
            return Err(());
        }

        Ok(Self {
            identity: value.into_boxed_slice(),
        })
    }
}
