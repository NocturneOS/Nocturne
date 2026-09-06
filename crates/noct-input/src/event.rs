use alloc::vec::Vec;

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

impl InputEvent {
    fn event_kind_raw(&self) -> u16 {
        match self {
            Self::Key { .. } => 0,

            Self::MouseMove { .. } => 1,
            Self::MouseButton { .. } => 2,
            Self::MouseWheel { .. } => 3,
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut vector: Vec<u8> = Vec::with_capacity(size_of::<Self>());

        let event_kind = self.event_kind_raw().to_le_bytes();

        vector.extend_from_slice(&event_kind);

        match self {
            Self::Key { code, pressed } => {
                vector.push(*code);
                vector.push(*pressed as u8);
            },
            Self::MouseMove { dx, dy } => {
                vector.extend_from_slice(&dx.to_le_bytes());
                vector.extend_from_slice(&dy.to_le_bytes());
            },
            Self::MouseButton { button, pressed } => {
                vector.push(button.serialize());
                vector.push(*pressed as u8);
            },
            Self::MouseWheel { direction } => {
                vector.push(*direction as _);
            },
        }

        vector
    }
}