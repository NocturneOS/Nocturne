use alloc::vec::Vec;

use crate::{keyboard::KeyCode, mouse::{MouseButton, MouseWheelDirection}};

/// Size of the userspace-visible input event record. (sizeof(event_t))
///
/// The userspace ABI reserves a fixed 32-byte record (future-proofing) so that new event
/// variants can be added without changing the size of the buffer that
/// programs pass to `read()`.
pub const EVENT_WIRE_SIZE: usize = 32;

#[derive(Debug, Clone, Copy)]
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

    /// Serializes the event into a fixed-size userspace record.
    ///
    /// Returns the number of bytes written (`EVENT_WIRE_SIZE`), or `None`
    /// when `out` is too small.
    pub fn serialize_into(&self, out: &mut [u8]) -> Option<usize> {
        if out.len() < EVENT_WIRE_SIZE {
            return None;
        }

        // Keep the whole record deterministic, including the reserved tail.
        out[..EVENT_WIRE_SIZE].fill(0);

        let event_kind = self.event_kind_raw().to_le_bytes();

        out[..2].copy_from_slice(&event_kind);

        match self {
            Self::Key { code, pressed } => {
                out[2] = *code;
                out[3] = *pressed as u8;
            },
            Self::MouseMove { dx, dy } => {
                out[2..6].copy_from_slice(&dx.to_le_bytes());
                out[6..10].copy_from_slice(&dy.to_le_bytes());
            },
            Self::MouseButton { button, pressed } => {
                out[2] = button.serialize();
                out[3] = *pressed as u8;
            },
            Self::MouseWheel { direction } => {
                out[2] = *direction as _;
            },
        }

        Some(EVENT_WIRE_SIZE)
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut vector = alloc::vec![0u8; EVENT_WIRE_SIZE];

        self.serialize_into(&mut vector)
            .expect("EVENT_WIRE_SIZE buffer is always large enough");

        vector
    }
}