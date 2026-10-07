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
            self.render(None);
        }
    }

    pub fn print_str(&mut self, input: &str) {
        self.console.print_str(input);

        if input.contains('\n') {
            self.render(None);
        }
    }

    pub fn render(&mut self, start_position: Option<(usize, usize)>) {
        // Try lock the video spinlock.
        // If can't, just don't render, as it may be locked by user program (it's okay).
        let Some(mut video_handle_lock) = noct_video::CURRENT_VIDEO_MODE.try_lock() else {
            return;
        };

        let mut video_canvas = noct_video::canvas::Canvas::new(video_handle_lock.as_mut().unwrap());

        video_canvas.fill(0);

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
                let charwidth = char.get_width();

                let col_offset = column * 8;
                let row_offset = row * 16;

                for i in 0..16_usize {
                    for j in 0..charwidth {
                        let pix = char.get_pixel(j, i);

                        if !pix {
                            continue;
                        }

                        video_canvas.put_pixel(
                            col_offset + j,
                            row_offset + i,
                            self.current_color as _,
                        );
                    }
                }
            }
        }

        // unsafe { screen_update() };
    }
}
