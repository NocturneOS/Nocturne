use noct_video::canvas::Canvas;

use crate::console::{CELL_HEIGHT, CELL_WIDTH, Cell, Console};

pub struct RenderedConsole {
    console: Console,
}

impl RenderedConsole {
    pub fn new(console: Console) -> Self {
        Self { console }
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
        // If we can't, just don't render, as it may be locked by a user program
        // (that's okay).
        let Some(mut video_handle_lock) = noct_video::CURRENT_VIDEO_MODE.try_lock() else {
            return;
        };

        let Some(video_mode) = video_handle_lock.as_mut() else {
            return;
        };

        let mut video_canvas = Canvas::new(video_mode);

        video_canvas.fill(0);

        let dimensions = self.console.dimensions();
        let rows = dimensions.rows;
        let columns = dimensions.columns;

        let (cursor_row, cursor_column) = self.console.position();
        let cursor_visible = self.console.cursor_visible();

        // The console keeps the cursor in range, but clamp defensively because
        // `position()` is also public.
        let cursor_row = cursor_row.min(rows.saturating_sub(1));
        let cursor_column = cursor_column.min(columns.saturating_sub(1));

        for row in 0..rows {
            for column in 0..columns {
                let Some(cell) = self.console.cell(row, column).copied() else {
                    continue;
                };

                // Is cursor on the current position?
                let is_cursor = cursor_visible && row == cursor_row && column == cursor_column;

                // The cursor may be on an empty cell. In that case it is the
                // only reason to draw the cell at all.
                if cell.ch == '\0' && !is_cursor {
                    continue;
                }

                self.paint_cell(&mut video_canvas, row, column, cell, is_cursor);
            }
        }
    }

    fn paint_cell(&self, canvas: &mut Canvas, row: usize, column: usize, cell: Cell, cursor: bool) {
        // Inverse video for the cursor: the cell background becomes the
        // character's foreground and vice versa.
        let (foreground, background) = if cursor {
            (cell.bg, cell.fg)
        } else {
            (cell.fg, cell.bg)
        };

        let glyph = if cell.ch == '\0' {
            None
        } else {
            unifont::get_glyph(cell.ch).or_else(|| unifont::get_glyph('?'))
        };

        let width = glyph.map(|glyph| glyph.get_width()).unwrap_or(CELL_WIDTH);

        let x_offset = column * CELL_WIDTH;
        let y_offset = row * CELL_HEIGHT;

        // The full render starts with a black screen, so normally only the
        // cells that actually have a background need to be filled. The cursor
        // always fills its cell.
        if cursor || background != 0 {
            // Render the cursor
            for y in 0..CELL_HEIGHT {
                for x in 0..width {
                    canvas.put_pixel(x_offset + x, y_offset + y, background);
                }
            }
        }

        if let Some(glyph) = glyph {
            // Render the character
            for y in 0..CELL_HEIGHT {
                for x in 0..width {
                    if glyph.get_pixel(x, y) {
                        canvas.put_pixel(x_offset + x, y_offset + y, foreground);
                    }
                }
            }
        }
    }
}
