use alloc::vec;
use alloc::vec::Vec;

/// Width of a character cell in pixels.
pub const CELL_WIDTH: usize = 8;
/// Height of a character cell in pixels.
pub const CELL_HEIGHT: usize = 16;

pub const DEFAULT_FG: u32 = 0x00_ffffff;
pub const DEFAULT_BG: u32 = 0x00_0000;

const ANSI_COLORS: [u32; 8] = [
    0x00_0000, // Black
    0xff_0000, // Red
    0x00_ff00, // Green
    0xffff00,  // Yellow
    0x00_00ff, // Blue
    0xff_00ff, // Magenta
    0x00_ffff, // Cyan
    0xffffff,  // White
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Dimensions {
    pub rows: usize,
    pub columns: usize,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Cell {
    pub ch: char,
    pub fg: u32,
    pub bg: u32,
}

impl Default for Cell {
    fn default() -> Self {
        Self {
            ch: '\0',
            fg: DEFAULT_FG,
            bg: DEFAULT_BG,
        }
    }
}

pub struct Console {
    dimensions: Dimensions,
    row: usize,
    column: usize,

    matrix: Vec<Cell>,

    current_fg: u32,
    current_bg: u32,
    cursor_visible: bool,

    /// A character was written in the last column flag.
    /// The cursor stays on tha cell until the next printable
    /// character wraps to the following line.
    wrap_pending: bool,
}

impl Console {
    pub fn new(rows: usize, columns: usize) -> Self {
        Self {
            dimensions: Dimensions { rows, columns },
            row: 0,
            column: 0,
            matrix: vec![Cell::default(); rows * columns],
            current_fg: DEFAULT_FG,
            current_bg: DEFAULT_BG,
            cursor_visible: true,
            wrap_pending: false,
        }
    }

    pub fn resize(&mut self, rows: usize, columns: usize) {
        let mut matrix = vec![Cell::default(); rows * columns];

        let target_rows = rows.min(self.dimensions.rows);
        let target_columns = columns.min(self.dimensions.columns);

        for i in 0..target_rows {
            for j in 0..target_columns {
                matrix[i * columns + j] = self.matrix[i * self.dimensions.columns + j];
            }
        }

        self.matrix = matrix;
        self.dimensions = Dimensions { rows, columns };
        self.row = self.row.min(rows.saturating_sub(1));
        self.column = self.column.min(columns.saturating_sub(1));
        self.wrap_pending = false;
    }

    pub fn clear(&mut self) {
        self.matrix.fill(Cell::default());
    }

    pub fn dimensions(&self) -> &Dimensions {
        &self.dimensions
    }

    pub fn data_position(&self) -> usize {
        (self.row * self.dimensions.columns) + self.column
    }

    pub fn cell(&self, row: usize, column: usize) -> Option<&Cell> {
        self.matrix.get((row * self.dimensions.columns) + column)
    }

    pub fn get_character(&self, row: usize, column: usize) -> Option<&char> {
        self.cell(row, column).map(|cell| &cell.ch)
    }

    pub fn position(&self) -> (usize, usize) {
        (self.row, self.column)
    }

    pub fn cursor_visible(&self) -> bool {
        self.cursor_visible
    }

    pub fn set_cursor_visible(&mut self, visible: bool) {
        self.cursor_visible = visible;
    }

    pub fn current_line(&self) -> &[Cell] {
        let begin = self.row * self.dimensions.columns;
        let end = begin + self.dimensions.columns;

        &self.matrix[begin..end]
    }

    pub fn current_line_mut(&mut self) -> &mut [Cell] {
        let begin = self.row * self.dimensions.columns;
        let end = begin + self.dimensions.columns;

        &mut self.matrix[begin..end]
    }

    pub fn current_line_length(&self) -> usize {
        let line = self.current_line();

        line.iter().filter(|&a| *a != Cell::default()).count()
    }

    pub fn move_right(&mut self) {
        if self.dimensions.columns == 0 {
            return;
        }

        if self.wrap_pending {
            self.column = 0;
            self.advance_row();
            self.wrap_pending = false;
        } else if self.column + 1 >= self.dimensions.columns {
            self.wrap_pending = true;
        } else {
            self.column += 1;
        }
    }

    pub fn move_left(&mut self) {
        self.wrap_pending = false;

        if self.column > 0 {
            self.column -= 1;
        } else if self.row > 0 {
            self.row -= 1;
            self.column = self.dimensions.columns.saturating_sub(1);
        }
    }

    pub fn move_down(&mut self) {
        self.column = 0;
        self.wrap_pending = false;
        self.advance_row();
    }

    pub fn move_to_beginning(&mut self) {
        self.column = 0;
        self.wrap_pending = false;
    }

    fn advance_row(&mut self) {
        if self.dimensions.rows == 0 {
            self.row = 0;
            return;
        }

        if self.row + 1 >= self.dimensions.rows {
            self.scroll();
            self.row = self.dimensions.rows - 1;
        } else {
            self.row += 1;
        }
    }

    pub fn print_char(&mut self, character: char) {
        if self.dimensions.rows == 0 || self.dimensions.columns == 0 {
            return;
        }

        match character {
            '\n' => {
                self.move_down();
                return;
            }
            '\u{8}' => {
                // Backspace only moves the caret. Erasing is done by the
                // writer with the usual `\b \b` sequence.
                self.move_left();
                return;
            }
            '\r' => {
                self.move_to_beginning();
                return;
            }
            '\t' => {
                for _ in 0..4 {
                    self.print_char(' ');
                }
                return;
            }
            '\0' => return,
            _ => {}
        }

        if self.wrap_pending {
            self.column = 0;
            self.advance_row();
            self.wrap_pending = false;
        }

        let pos = self.data_position();

        self.matrix[pos] = Cell {
            ch: character,
            fg: self.current_fg,
            bg: self.current_bg,
        };

        self.move_right();
    }

    pub fn print_str(&mut self, input: &str) {
        let mut iterator = input.chars();

        while let Some(character) = iterator.next() {
            if character != '\u{1b}' {
                self.print_char(character);
                continue;
            }

            // Only CSI sequences are interpreted. A bare ESC (or a different
            // escape sequence) is ignored.
            if iterator.next() != Some('[') {
                continue;
            }

            let mut parameters = [0u32; 8];
            let mut parameter_count = 0usize;
            let mut current = 0u32;
            let mut has_digits = false;
            let mut private = false;

            let command = loop {
                let Some(character) = iterator.next() else {
                    return;
                };

                match character {
                    '0'..='9' => {
                        has_digits = true;
                        current = current
                            .saturating_mul(10)
                            .saturating_add(character as u32 - '0' as u32)
                            .min(9999);
                    }
                    ';' | ':' => {
                        if parameter_count < parameters.len() {
                            parameters[parameter_count] = current;
                            parameter_count += 1;
                        }

                        current = 0;
                        has_digits = false;
                    }
                    '?' => private = true,
                    '<' | '=' | '>' => {}
                    ' '..='/' => {}
                    '@'..='~' => {
                        if (has_digits || parameter_count > 0) && parameter_count < parameters.len()
                        {
                            parameters[parameter_count] = current;
                            parameter_count += 1;
                        }

                        break character;
                    }
                    _ => return,
                }
            };

            self.handle_csi(&parameters[..parameter_count], private, command);
        }
    }

    fn handle_csi(&mut self, parameters: &[u32], private: bool, command: char) {
        let parameter =
            |index: usize, default: u32| parameters.get(index).copied().unwrap_or(default);

        match command {
            'm' => self.set_graphics(parameters),
            'H' | 'f' => {
                let row = parameter(0, 1).max(1) as usize - 1;
                let column = parameter(1, 1).max(1) as usize - 1;

                self.set_position(column, row);
            }
            'J' => self.erase_display(parameter(0, 0)),
            'K' => self.erase_line(parameter(0, 0)),
            'h' if private => self.set_private_mode(parameters, true),
            'l' if private => self.set_private_mode(parameters, false),
            _ => {}
        }
    }

    fn set_private_mode(&mut self, parameters: &[u32], enabled: bool) {
        for &mode in parameters {
            // DECTCEM: show/hide cursor.
            if mode == 25 {
                self.cursor_visible = enabled;
            }
        }
    }

    fn set_graphics(&mut self, parameters: &[u32]) {
        if parameters.is_empty() {
            self.current_fg = DEFAULT_FG;
            self.current_bg = DEFAULT_BG;
            return;
        }

        let mut index = 0;

        while index < parameters.len() {
            let code = parameters[index];

            match code {
                // Reset
                0 => {
                    self.current_fg = DEFAULT_FG;
                    self.current_bg = DEFAULT_BG;
                }
                // Foreground
                30..=37 => self.current_fg = ANSI_COLORS[(code - 30) as usize],
                39 => self.current_fg = DEFAULT_FG,
                // Background
                40..=47 => self.current_bg = ANSI_COLORS[(code - 40) as usize],
                49 => self.current_bg = DEFAULT_BG,
                // Bright variants use the same palette for now.
                90..=97 => self.current_fg = ANSI_COLORS[(code - 90) as usize],
                100..=107 => self.current_bg = ANSI_COLORS[(code - 100) as usize],
                38 | 48 => {
                    // Extended colors (38;5;n / 38;2;r;g;b) are not supported
                    // yet, but their parameters must not be interpreted as
                    // separate SGR codes.
                    match parameters.get(index + 1).copied() {
                        Some(5) if index + 2 < parameters.len() => index += 2,
                        Some(2) if index + 4 < parameters.len() => index += 4,
                        _ => break,
                    }
                }
                _ => {}
            }

            index += 1;
        }
    }

    // For `[K` handling.
    fn erase_line(&mut self, code: u32) {
        let rows = self.dimensions.rows;
        let columns = self.dimensions.columns;

        if rows == 0 || columns == 0 {
            return;
        }

        let row = self.row.min(rows - 1);
        let column = self.column.min(columns - 1);
        let line_start = row * columns;
        let line = &mut self.matrix[line_start..line_start + columns];

        match code {
            0 => line[column..].fill(Cell::default()),
            1 => line[..=column].fill(Cell::default()),
            2 => line.fill(Cell::default()),
            _ => {}
        }
    }

    // Handle `[J` - erase display.
    fn erase_display(&mut self, code: u32) {
        let rows = self.dimensions.rows;
        let columns = self.dimensions.columns;

        if rows == 0 || columns == 0 {
            return;
        }

        let row = self.row.min(rows - 1);
        let column = self.column.min(columns - 1);

        match code {
            // Clear from the current position to the end of the screen.
            0 => {
                let line_start = row * columns;

                self.matrix[line_start + column..line_start + columns].fill(Cell::default());
                self.matrix[(row + 1) * columns..].fill(Cell::default());
            }
            // Clear from the beginning to the current position.
            1 => {
                let line_start = row * columns;

                self.matrix[..line_start].fill(Cell::default());
                self.matrix[line_start..line_start + column + 1].fill(Cell::default());
            }
            // Clear the whole screen (not returning cursor position to home)
            2 | 3 => self.clear(),
            _ => {}
        }
    }

    pub fn scroll(&mut self) {
        let columns = self.dimensions.columns;

        if self.dimensions.rows == 0 || columns == 0 {
            return;
        }

        self.matrix.copy_within(columns.., 0);

        let last_line = self.matrix.len() - columns;
        self.matrix[last_line..].fill(Cell::default());
    }

    pub fn set_position(&mut self, x: usize, y: usize) {
        self.row = y.min(self.dimensions.rows.saturating_sub(1));
        self.column = x.min(self.dimensions.columns.saturating_sub(1));
        self.wrap_pending = false;
    }

    pub fn size_chars(&self) -> (usize, usize) {
        let dims = self.dimensions();

        (dims.rows, dims.columns)
    }
}
