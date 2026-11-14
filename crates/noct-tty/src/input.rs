use core::sync::atomic::{
    AtomicU8,
    Ordering::{Acquire, Release},
};

use lazy_static::lazy_static;
use noct_input_dispatcher::{EventQueue, InputSink, event::InputEvent};
use spin::Mutex;

const SCANCODE_TRANSLATION_TABLE: &[u8] = &[
    0, b'\x1b', b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9', b'0', b'-', b'=', b'\x08',
    b'\t', b'q', b'w', b'e', b'r', b't', b'y', b'u', b'i', b'o', b'p', b'[', b']', b'\n', 0, b'a',
    b's', b'd', b'f', b'g', b'h', b'j', b'k', b'l', b';', b'\'', b'`', 0, b'\\', b'z', b'x', b'c',
    b'v', b'b', b'n', b'm', b',', b'.', b'/', 0, 0, 0, b' ', 0,
];

const SCANCODE_TRANSLATION_TABLE_SHIFT: &[u8] = &[
    0, b'\x1b', b'!', b'@', b'#', b'$', b'%', b'^', b'&', b'*', b'(', b')', b'_', b'+', b'\x08',
    b'\t', b'Q', b'W', b'E', b'R', b'T', b'Y', b'U', b'I', b'O', b'P', b'{', b'}', b'\n', 0, b'A',
    b'S', b'D', b'F', b'G', b'H', b'J', b'K', b'L', b':', b'"', b'~', 0, b'|', b'Z', b'X', b'C',
    b'V', b'B', b'N', b'M', b'<', b'>', b'?', 0, 0, 0, b' ', 0,
];

const _: &[()] = &[assert!(
    SCANCODE_TRANSLATION_TABLE.len() == SCANCODE_TRANSLATION_TABLE_SHIFT.len()
)];

use bitflags::bitflags;

bitflags! {
    pub struct InputState: u8 {
        const ShiftPressed = 1 << 0;
        const CapsEnabled = 1 << 1;
    }
}

static TTY_INPUT_STATE: AtomicU8 = AtomicU8::new(0);

lazy_static! {
    /// The TTY owns its stdin queue now. It is only touched by the input
    /// dispatcher thread (producer) and read syscalls (consumer), never by an
    /// IRQ handler.
    /// Since the TTY is a global thing, making it static is okay.
    static ref TTY_QUEUE: Mutex<EventQueue> = Mutex::new(EventQueue::new());
}

struct TtyInputSink;

impl InputSink for TtyInputSink {
    fn push_event(&self, event: InputEvent) {
        // The TTY only cares about keyboard events.
        if matches!(event, InputEvent::Key { .. }) {
            TTY_QUEUE.lock().push(event);
        }
    }
}

static TTY_SINK: TtyInputSink = TtyInputSink;

pub fn init() {
    noct_input_dispatcher::register_sink(&TTY_SINK);
}

/// Returns the next translated character, or `None` when no character is
/// currently available.
pub fn try_read_char() -> Option<u8> {
    let mut queue = TTY_QUEUE.lock();

    loop {
        let event = queue.get_raw()?;

        if let Some(character) = translate(event) {
            return Some(character);
        }
    }
}

fn translate(event: InputEvent) -> Option<u8> {
    let InputEvent::Key { code, pressed } = event else {
        return None;
    };

    match code {
        // Left or Right Shift
        0x2A | 0x36 => {
            if pressed {
                TTY_INPUT_STATE.fetch_or(InputState::ShiftPressed.bits(), Release);
            } else {
                TTY_INPUT_STATE.fetch_and(!InputState::ShiftPressed.bits(), Release);
            }

            None
        }
        // Caps Lock toggles on press only, not on both press and release.
        0x3A => {
            if pressed {
                TTY_INPUT_STATE.fetch_xor(InputState::CapsEnabled.bits(), Release);
            }

            None
        }
        key if pressed => {
            let state = InputState::from_bits_truncate(TTY_INPUT_STATE.load(Acquire));

            let shift = state.contains(InputState::ShiftPressed);
            let caps = state.contains(InputState::CapsEnabled);

            let mut character = if shift {
                SCANCODE_TRANSLATION_TABLE_SHIFT.get(key as usize).copied()?
            } else {
                SCANCODE_TRANSLATION_TABLE.get(key as usize).copied()?
            };

            // Zero entries are non-printing keys (Ctrl, Alt, ...).
            if character == 0 {
                return None;
            }

            // Caps Lock affects letters only. With Shift held it inverts the
            // shift state instead of uppercasing the shifted character.
            if caps && character.is_ascii_alphabetic() {
                character = if shift {
                    character.to_ascii_lowercase()
                } else {
                    character.to_ascii_uppercase()
                };
            }

            Some(character)
        }
        _ => None,
    }
}
