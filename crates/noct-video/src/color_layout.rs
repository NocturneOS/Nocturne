#[derive(Debug, Clone, PartialEq)]
pub struct ColorLayout {
    red_offset: u8,
    green_offset: u8,
    blue_offset: u8,
}

impl ColorLayout {
    pub fn new(red_offset: u8, green_offset: u8, blue_offset: u8) -> Self {
        Self {
            red_offset,
            green_offset,
            blue_offset,
        }
    }

    pub fn red_offset(&self) -> u8 {
        self.red_offset
    }

    pub fn green_offset(&self) -> u8 {
        self.green_offset
    }

    pub fn blue_offset(&self) -> u8 {
        self.blue_offset
    }
}
