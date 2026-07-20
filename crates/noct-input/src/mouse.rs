#[derive(Copy, Clone, Debug)]
pub enum MouseButton {
    Left,
    Middle,
    Right,

    // Index of specific button (base buttons are NOT included!)
    // For 5-button mouse which has 3 base buttons (LMR) and 2 additional ones indexes will be 0 and 1.
    Custom(u8)
}

#[derive(Copy, Clone, Debug)]
pub enum MouseWheelDirection {
    Up,
    Down
}