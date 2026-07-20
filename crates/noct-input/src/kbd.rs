use crate::get;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SpecialKey {
    ESCAPE,
    BACKSPACE,
    TAB,
    ENTER,
    CtrlLeft,
    ShiftLeft,
    ShiftRight,
    PRINTSCREEN,
    ALT,
    CAPS,
    NUMLOCK,
    ScrollLock,
    HOME,
    UP,
    PageUp,
    LEFT,
    CENTER,
    RIGHT,
    END,
    DOWN,
    PageDown,
    INSERT,
    DELETE,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Key {
    Unknown,
    Special(SpecialKey),
    Functional(u8),
    Character(char),
}

static KEYS: &[Key] = &[
    Key::Unknown,
    Key::Special(SpecialKey::ESCAPE),
    Key::Character('1'),
    Key::Character('2'),
    Key::Character('3'),
    Key::Character('4'),
    Key::Character('5'),
    Key::Character('6'),
    Key::Character('7'),
    Key::Character('8'),
    Key::Character('9'),
    Key::Character('0'),
    Key::Character('-'),
    Key::Character('='),
    Key::Special(SpecialKey::BACKSPACE),
    Key::Special(SpecialKey::TAB),
    Key::Character('q'),
    Key::Character('w'),
    Key::Character('e'),
    Key::Character('r'),
    Key::Character('t'),
    Key::Character('y'),
    Key::Character('u'),
    Key::Character('i'),
    Key::Character('o'),
    Key::Character('p'),
    Key::Character('['),
    Key::Character(']'),
    Key::Special(SpecialKey::ENTER),
    Key::Special(SpecialKey::CtrlLeft),
    Key::Character('a'),
    Key::Character('s'),
    Key::Character('d'),
    Key::Character('f'),
    Key::Character('g'),
    Key::Character('h'),
    Key::Character('j'),
    Key::Character('k'),
    Key::Character('l'),
    Key::Character(';'),
    Key::Character('\''),
    Key::Character('`'),
    Key::Special(SpecialKey::ShiftLeft),
    Key::Character('\\'),
    Key::Character('z'),
    Key::Character('x'),
    Key::Character('c'),
    Key::Character('v'),
    Key::Character('b'),
    Key::Character('n'),
    Key::Character('m'),
    Key::Character(','),
    Key::Character('.'),
    Key::Character('/'),
    Key::Special(SpecialKey::ShiftRight),
    Key::Special(SpecialKey::PRINTSCREEN),
    Key::Special(SpecialKey::ALT),
    Key::Character(' '),
    Key::Special(SpecialKey::CAPS),
    Key::Functional(1),
    Key::Functional(2),
    Key::Functional(3),
    Key::Functional(4),
    Key::Functional(5),
    Key::Functional(6),
    Key::Functional(7),
    Key::Functional(8),
    Key::Functional(9),
    Key::Functional(10),
    Key::Special(SpecialKey::NUMLOCK),
    Key::Special(SpecialKey::ScrollLock),
    Key::Special(SpecialKey::HOME),
    Key::Special(SpecialKey::UP),
    Key::Special(SpecialKey::PageUp),
    Key::Character('-'),
    Key::Special(SpecialKey::LEFT),
    Key::Special(SpecialKey::CENTER),
    Key::Special(SpecialKey::RIGHT),
    Key::Character('+'),
    Key::Special(SpecialKey::END),
    Key::Special(SpecialKey::DOWN),
    Key::Special(SpecialKey::PageDown),
    Key::Special(SpecialKey::INSERT),
    Key::Special(SpecialKey::DELETE),
];

/// Returns a key and pressed state
pub fn parse_scancode(scancode: u8) -> Option<(Key, bool)> {
    let is_pressed = (scancode & 0x80) == 0;
    let scancode = scancode & !0x80;
    let key: Option<&Key> = KEYS.get(scancode as usize);

    key.map(|&a| (a, is_pressed))
}

#[derive(Debug)]
pub enum CharKey {
    Char(char),
    Key(Key, bool),
}

unsafe extern "C" {
    fn parse_char(ch: u32) -> u32;
}

pub fn get_key() -> CharKey {
    let key = get();

    let ch = unsafe { parse_char(key) };

    if ch == 0 {
        let (pressed, key) = ((key & 0x80) == 0, key & !0x80);

        let k = *KEYS.get(key as usize).unwrap_or(&Key::Unknown);

        CharKey::Key(k, pressed)
    } else {
        if ch == 0x0a {
            return CharKey::Key(Key::Special(SpecialKey::ENTER), true);
        } else if ch == 0x7f {
            return CharKey::Key(Key::Special(SpecialKey::BACKSPACE), true);
        } else if ch == 0x00445b1b {
            return CharKey::Key(Key::Special(SpecialKey::LEFT), true);
        } else if ch == 0x00435b1b {
            return CharKey::Key(Key::Special(SpecialKey::RIGHT), true);
        } else if ch == 0x00415b1b {
            return CharKey::Key(Key::Special(SpecialKey::UP), true);
        } else if ch == 0x00425b1b {
            return CharKey::Key(Key::Special(SpecialKey::DOWN), true);
        } else if ch == 0x7e335b1b {
            return CharKey::Key(Key::Special(SpecialKey::DELETE), true);
        }

        let ret = match char::from_u32(ch) {
            Some(ch) => ch,
            None => {
                panic!("Handle character: {ch:x}");
            }
        };

        CharKey::Char(ret)
    }
}
