// use noct_video::screen_update;

use noct_logger::qemu_log;

use crate::console::{AttributeValue, Console};

pub struct RenderedConsole {
    console: Console,
    current_color: u32,
}

impl RenderedConsole {
    pub fn new(console: Console) -> Self {
        Self {
            console,
            current_color: 0x00_ffffff,
        }
    }

    pub fn console(&self) -> &Console {
        &self.console
    }

    pub fn console_mut(&mut self) -> &mut Console {
        &mut self.console
    }

    pub fn print_char(&mut self, c: char) {
        self.console.print_char(c);

        if c == '\n' {
            unsafe {
                // noct_screen::clean_screen();
            }

            self.render(None);
        }
    }

    pub fn print_str(&mut self, input: &str) {
        self.console.print_str(input);

        if input.contains('\n') {
            unsafe {
                // noct_screen::clean_screen();
            }

            self.render(None);
        }
    }

    pub fn render(&mut self, start_position: Option<(usize, usize)>) {
        let mut video_handle_lock = noct_video::CURRENT_VIDEO_MODE.lock();
        let mut video_canvas = noct_video::canvas::Canvas::new(video_handle_lock.as_mut().unwrap());

        let dimensions = self.console.dimensions();

        let start_row = start_position.map(|(row, _)| row).unwrap_or(0);
        let start_column = start_position.map(|(_, column)| column).unwrap_or(0);

        for row in start_row..dimensions.rows {
            for column in start_column..dimensions.columns {
                let char = self.console.get_character(row, column).unwrap();

                if *char == char::default() {
                    continue;
                }

                if let Some(attribute) = self.console.get_attribute(row, column) {
                    match attribute.attribute_value {
                        AttributeValue::Color(color) => {
                            self.current_color = color;
                        }
                    }
                }

                let char = unifont::get_glyph(*char).expect("Couldn't find a glyph for character!");

                for i in 0..16_usize {
                    for j in 0..char.get_width() {
                        let pix = char.get_pixel(j, i);

                        if pix {
                            video_canvas.put_pixel(
                                (column * 8) + j,
                                (row * 16) + i,
                                self.current_color as _,
                            );
                        }
                    }
                }

                // font.draw_character(
                //     if char.is_ascii() {
                //         *char as u16
                //     } else {
                //         let mut dst = [0u8; 4];
                //         char.encode_utf8(&mut dst);

                //         let value = u32::from_be_bytes(dst) >> 16;
                //         value as u16
                //     },
                //     column * 8,
                //     row * 16,
                //     self.current_color,
                // );
            }
        }

        // unsafe { screen_update() };
    }
}
