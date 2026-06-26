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

pub struct Console {
    dimensions: Dimensions,
    row: usize,
    column: usize,
    data: Vec<char>,
    attributes: Vec<Attribute>,
}

impl Console {
    pub fn new(rows: usize, columns: usize) -> Self {
        Self {
            dimensions: Dimensions { rows, columns },
            row: 0,
            column: 0,
            data: vec![char::default(); rows * columns],
            attributes: vec![],
        }
    }

    pub fn resize(&mut self, rows: usize, columns: usize) {
        let mut data = vec![char::default(); rows * columns];

        let target_rows = rows.min(self.dimensions.rows);
        let target_columns = columns.min(self.dimensions.columns);

        for i in 0..target_rows {
            for j in 0..target_columns {
                data[i * columns + j] = self.data[i * self.dimensions.columns + j];
            }
        }

        self.data = data;
        self.dimensions = Dimensions { rows, columns };
    }

    pub fn clear(&mut self) {
        self.data.fill(char::default());
        self.attributes.clear();
    }

    pub fn dimensions(&self) -> &Dimensions {
        &self.dimensions
    }

    pub fn data_position(&self) -> usize {
        (self.row * self.dimensions.columns) + self.column
    }

    pub fn get_character(&self, row: usize, column: usize) -> Option<&char> {
        self.data.get((row * self.dimensions.columns) + column)
    }

    pub fn position(&self) -> (usize, usize) {
        (self.row, self.column)
    }

    pub fn current_line(&self) -> &[char] {
        let begin = self.row * self.dimensions.columns;
        let end = begin + self.dimensions.columns;

        &self.data[begin..end]
    }

    pub fn current_line_mut(&mut self) -> &mut [char] {
        let begin = self.row * self.dimensions.columns;
        let end = begin + self.dimensions.columns;

        &mut self.data[begin..end]
    }

    pub fn current_line_length(&self) -> usize {
        let line = self.current_line();

        line.iter().filter(|&a| *a != char::default()).count()
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

        self.data[pos] = character;

        self.move_right();
    }

    pub fn get_attribute(&self, row: usize, column: usize) -> Option<&Attribute> {
        self.attributes
            .iter()
            .find(|a| a.row == row && a.column == column)
    }

    pub fn print_str(&mut self, input: &str) {
        // qemu_note!("Printing string: {input:?}");

        let mut iterator = input.chars();

        while let Some(i) = iterator.next() {
            if i == '\u{1b}' {
                let next = iterator.next();

                if next == Some('[') {
                    // Read digits until non-digit
                    let mut digits = String::new();

                    let mut values: Vec<u32> = vec![];

                    let mut last_char = char::default();
                    while let Some(c) = iterator.next() {
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
                    }

                    //qemu_note!("Values: {values:?}; Letter: {last_char:?}");

                    if last_char == 'm' {
                        let code = *values.last().unwrap_or(&0);

                        let color = AttributeValue::Color(if code == 0 {
                            0x00_ffffff
                        } else {
                            ANSI_COLORS[(code - 30) as usize]
                        });

                        self.attributes.push(Attribute {
                            row: self.row,
                            column: self.column,
                            attribute_value: color,
                        });

                        continue;
                    } else if last_char == 'H' {
                        if values.is_empty() {
                            self.row = 0;
                            self.column = 0;
                        } else {
                            let row = *values.get(0).unwrap_or(&1);
                            let column = *values.get(1).unwrap_or(&1);

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

                            line[start_position..end_position].fill(char::default());
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
        self.data.copy_within(self.dimensions.columns.., 0);

        let last_line = self.data.len() - self.dimensions.columns;
        self.data[last_line..].fill(char::default());
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
