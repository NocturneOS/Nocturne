use crate::{keyboard::KeyCode, mouse::{MouseButton, MouseWheelDirection}};

#[derive(Debug, Clone)]
pub enum InputEvent {
    Key { code: KeyCode, pressed: bool },
    
    MouseMove { dx: i32, dy: i32 },
    MouseButton { button: MouseButton, pressed: bool },
    MouseWheel { direction: MouseWheelDirection },

    // NDRAEY: I'm not sure PS/2 has delta reporting for mouse wheel. I'll check it later
    // MouseWheel { delta: i8 },
}
