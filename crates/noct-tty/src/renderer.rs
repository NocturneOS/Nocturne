use noct_video::canvas::Canvas;

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
            self.render();
        }
    }

    pub fn print_str(&mut self, input: &str) {
        self.console.print_str(input);

        if input.contains('\n') {
            self.render();
        }
    }

    pub fn render(&mut self) {
        // Try lock the video spinlock.
        // If can't, just don't render, as it may be locked by user program (it's okay).
        let Some(mut video_handle_lock) = noct_video::CURRENT_VIDEO_MODE.try_lock() else {
            return;
        };

        let mut video_canvas = noct_video::canvas::Canvas::new(video_handle_lock.as_mut().unwrap());

        video_canvas.fill(0);

        let dimensions = self.console.dimensions();

        let (c_row, c_col) = self.console.position();

        // Render the matrix
        for row in 0..dimensions.rows {
            for column in 0..dimensions.columns {
                let char = self.console.get_character(row, column).unwrap();

                if *char == char::default() {
                    continue;
                }

                if let Some((bg, fg)) = self.console.get_attribute(row, column) {
                    // match attribute.attribute_value {
                    //     AttributeValue::Color(color) => {
                    //         self.current_color = color;
                    //     }
                    // }

                    self.current_color = fg;
                }

                let char = unifont::get_glyph(*char).unwrap_or(unifont::get_glyph('?').unwrap());
                let charwidth = char.get_width();

                let col_offset = column * 8;
                let row_offset = row * 16;
                
                // TODO: Use that for cursor display.
                // let is_cursor_char = column == c_col && row == c_row;

                for i in 0..16_usize {
                    for j in 0..charwidth {
                        let pix = char.get_pixel(j, i);

                        if pix {
                            video_canvas.put_pixel(
                                col_offset + j,
                                row_offset + i,
                                self.current_color as _,
                            );
                        }
                    }
                }
            }
        }

        // unsafe { screen_update() };
    }
}
