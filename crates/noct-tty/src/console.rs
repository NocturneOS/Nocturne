use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use noct_logger::qemu_log;

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

#[derive(Debug)]
pub struct Dimensions {
    pub rows: usize,
    pub columns: usize,
}

pub enum AttributeValue {
    Color(u32),
}

pub struct Attribute {
    pub row: usize,
    pub column: usize,
    pub attribute_value: AttributeValue,
}

#[derive(Copy, Clone, Default, PartialEq)]
pub struct Cell {
    pub ch: char,
    pub fg: u32,
    pub bg: u32,
}

pub struct Console {
    dimensions: Dimensions,
    row: usize,
    column: usize,

    matrix: Vec<Cell>
}

impl Console {
    pub fn new(rows: usize, columns: usize) -> Self {
        Self {
            dimensions: Dimensions { rows, columns },
            row: 0,
            column: 0,
            matrix: vec![Cell::default(); rows * columns],
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

    pub fn get_character(&self, row: usize, column: usize) -> Option<&char> {
        self.matrix.get((row * self.dimensions.columns) + column).map(|x| &x.ch)
    }

    pub fn position(&self) -> (usize, usize) {
        (self.row, self.column)
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
        self.column += 1;

        if self.column >= self.dimensions.columns {
            self.column = 0;
            self.row += 1;
        }
    }

    pub fn move_left(&mut self) {
        if self.column == 0 {
            self.row = self.row.saturating_sub(1);

            self.column = self.current_line_length();
        }

        self.column = self.column.saturating_sub(1);
    }

    pub fn move_down(&mut self) {
        self.column = 0;
        self.row += 1;
    }

    pub fn move_to_beginning(&mut self) {
        self.column = 0;
    }

    pub fn print_char(&mut self, character: char) {
        if self.row >= self.dimensions.rows {
            self.scroll();
            self.row = self.dimensions.rows - 1;
        }

        let pos = self.data_position();

        if character == '\n' {
            self.move_down();
            return;
        } else if character as u32 == 8 {
            // Backspace
            self.move_left();
            // self.data[pos] = char::default();
            return;
        } else if character == '\r' {
            self.move_to_beginning();
            return;
        } else if character == '\t' {
            //self.column += 4;
            for _ in 0..4 {
                self.print_char(' ');
            }
            return;
        }

        self.matrix[pos] = Cell { ch: character, bg: 0x00_00_00_00, fg: 0x00_ffffff };

        self.move_right();
    }

    pub fn get_attribute(&self, row: usize, column: usize) -> Option<(u32, u32)> {
        let cell = &self.matrix.get(row * self.dimensions.columns + column);

        cell.map(|x| (x.bg, x.fg))
    }

    pub fn print_str(&mut self, input: &str) {
        // qemu_note!("Printing string: {input:?}");

        let mut iterator = input.chars();

        while let Some(i) = iterator.next() {
            if i == '\u{1b}' {
                let next = iterator.next();

                if next == Some('[') {
                    // Read digits until non-digit
                    let mut digits = String::with_capacity(4);

                    let mut values: Vec<u32> = Vec::with_capacity(2);

                    let mut counter = 0;

                    let mut last_char = char::default();

                    // Consume bytes until it's non-digit character (4 MAX).
                    while let Some(c) = iterator.next() && counter < 4 {
                        if c.is_ascii_digit() {
                            digits.push(c);
                        } else if c == ';' {
                            let value = digits.parse::<u32>();

                            if let Ok(value) = value {
                                values.push(value);
                            }

                            digits.clear();
                        } else {
                            let value = digits.parse::<u32>();

                            if let Ok(value) = value {
                                values.push(value);
                            }

                            last_char = c;
                            break;
                        }

                        counter += 1;
                    }

                    //qemu_note!("Values: {values:?}; Letter: {last_char:?}");

                    if last_char == 'm' {
                        let code = *values.last().unwrap_or(&0);

                        let color = if code == 0 {
                            0x00_ffffff
                        } else {
                            *ANSI_COLORS.get((code - 30) as usize).unwrap_or(&0x00_ffffff)
                        };

                        self.matrix[self.row * self.dimensions.columns + self.column].fg = color;

                        continue;
                    } else if last_char == 'H' {
                        if values.is_empty() {
                            self.row = 0;
                            self.column = 0;
                        } else {
                            let row = values.get(0).copied().unwrap_or(1).clamp(0, self.dimensions.rows as u32 - 1);
                            let column = values.get(1).copied().unwrap_or(1).clamp(0, self.dimensions.columns as u32 - 1);

                            // qemu_note!("Set position: {:?}", (row, column));

                            self.row = row.saturating_sub(1) as usize;
                            self.column = column.saturating_sub(1) as usize;
                        }
                    } else if last_char == 'J' {
                        let code = *values.last().unwrap_or(&0);

                        if code == 2 {
                            self.clear();
                        }
                    } else if last_char == 'K' {
                        let code = *values.last().unwrap_or(&0);

                        if code == 0 {
                            let start_position = self.column;
                            let end_position = self.dimensions.columns - 1;
                            let line = self.current_line_mut();

                            line[start_position..end_position].fill(Cell::default());
                        }
                    } else {
                        qemu_log!("ERROR: Unknown letter: {last_char:?}");
                    }
                }

                continue;
            }

            self.print_char(i);
        }
    }

    pub fn scroll(&mut self) {
        self.matrix.copy_within(self.dimensions.columns.., 0);

        let last_line = self.matrix.len() - self.dimensions.columns;
        self.matrix[last_line..].fill(Cell::default());
    }

    pub fn set_position(&mut self, x: usize, y: usize) {
        self.row = y;
        self.column = x;
    }

    pub fn size_chars(&self) -> (usize, usize) {
        let dims = self.dimensions();

        (dims.rows, dims.columns)
    }
}
