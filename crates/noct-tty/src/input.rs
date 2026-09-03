use core::sync::atomic::{
    AtomicU8, AtomicUsize,
    Ordering::{Acquire, Release},
};

use noct_input_dispatcher::{EventQueue, event::InputEvent};

static INPUT_FD: AtomicUsize = AtomicUsize::new(0);

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

pub fn init() {
    let fd = noct_input_dispatcher::register_this();

    INPUT_FD.store(fd, Release);
}

pub fn input_fd() -> usize {
    INPUT_FD.load(Acquire)
}

pub fn get_key_from(evq: &mut EventQueue) -> Option<(u8, bool)> {
    match evq.get_raw()? {
        InputEvent::Key { code, pressed } => {
            noct_sched::resume_group(noct_sched::thread::ThreadWaitReason::InputEvent);

            Some((code, pressed))
        }
        _ => None,
    }
}

pub fn get_char(evq: &mut EventQueue) -> Option<u8> {
    let (key, pressed) = get_key_from(evq)?;

    match key {
        // Left or Right shift
        0x2A | 0x36 => {
            if pressed {
                TTY_INPUT_STATE.fetch_or(InputState::ShiftPressed.bits(), Release);
            } else {
                TTY_INPUT_STATE.fetch_and(!InputState::ShiftPressed.bits(), Release);
            }
            
            None
        }
        // Caps Lock
        0x3A => {
            TTY_INPUT_STATE.fetch_xor(InputState::CapsEnabled.bits(), Release);
            None
        }
        key if pressed => {
            let state = InputState::from_bits(TTY_INPUT_STATE.load(Acquire)).unwrap();

            let ch = if state.contains(InputState::ShiftPressed) {
                SCANCODE_TRANSLATION_TABLE_SHIFT
                    .get(key as usize)
                    .copied()?
            } else {
                SCANCODE_TRANSLATION_TABLE.get(key as usize).copied()?
            };

            let ch = if state.contains(InputState::CapsEnabled) {
                ch.to_ascii_uppercase()
            } else {
                ch
            };

            Some(ch)
        }
        _ => None,
    }
}
