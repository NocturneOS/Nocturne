#[derive(Copy, Clone, Debug)]
pub enum MouseButton {
    Left,
    Middle,
    Right,

    // Index of specific button (base buttons are NOT included!)
    // For 5-button mouse which has 3 base buttons (LMR) and 2 additional ones indexes will be 0 and 1.
    Custom(u8)
}

impl MouseButton {
    pub fn serialize(&self) -> u8 {
        match self {
            Self::Left => 0,
            Self::Middle => 1,
            Self::Right => 2,
            Self::Custom(cusbtn) => 3 + cusbtn,
        }
    }
}

#[derive(Copy, Clone, Debug)]
#[repr(u8)]
pub enum MouseWheelDirection {
    Up = 0,
    Down = 1
}