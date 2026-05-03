#[derive(Debug, Clone, Copy)]
pub struct Time {
    year: u16,
    month: u8,
    day: u8,
    hour: u8,
    minute: u8,
    second: u8
}

impl Time {
    pub fn new(
        year: u16,
        month: u8,
        day: u8,
        hour: u8,
        minute: u8,
        second: u8,
    ) -> Result<Self, TimeError> {
        if month < 1 || month > 12 {
            return Err(TimeError::InvalidMonth);
        }
        if hour >= 24 {
            return Err(TimeError::InvalidHour);
        }
        if minute >= 60 {
            return Err(TimeError::InvalidMinute);
        }
        if second >= 60 {
            return Err(TimeError::InvalidSecond);
        }

        let time = Self {
            year,
            month,
            day,
            hour,
            minute,
            second,
        };

        if day < 1 || day > (Self::days_in_month(&time)? as u8) {
            return Err(TimeError::InvalidDay);
        }

        Ok(time)
    }

    /// Returns `true` if the given year is a leap year in the Gregorian calendar.
    pub fn is_leap_year(&self) -> bool {
        Self::is_leap_year_inner(self.year)
    }

    fn is_leap_year_inner(year: u16) -> bool {
        (year % 4 == 0) && (year % 100 != 0 || year % 400 == 0)
    }


    /// Returns the number of days in a given month (1‑based) for a specific year.
    fn days_in_month_inner(month: u8, year: u16) -> Result<u32, TimeError> {
        match month {
            1 | 3 | 5 | 7 | 8 | 10 | 12 => Ok(31),
            4 | 6 | 9 | 11 => Ok(30),
            2 => {
                if Self::is_leap_year_inner(year) {
                    Ok(29)
                } else {
                    Ok(28)
                }
            }
            _ => Err(TimeError::InvalidMonth),
        }
    }

    pub fn days_in_month(&self) -> Result<u32, TimeError> {
        Self::days_in_month_inner(self.month, self.year)
    }

    /// Returns the 1‑based day-of-year number for a given date.
    fn day_of_year(&self) -> Result<u32, TimeError> {
        let mut days = 0;
        for m in 1..self.month {
            days += Self::days_in_month_inner(m, self.year)?;
        }
        Ok(days + self.day as u32)
    }

    /// Converts a UTC date and time to a Unix timestamp (seconds since 1970-01-01 00:00:00 UTC).
    pub fn to_unix_timestamp(&self) -> Result<i64, TimeError> {
        // Start with whole years, ignoring leap days for now
        let mut days = (self.year - 1970) as i64 * 365;

        // Account for leap years in the range between 1970 and the target year
        if self.year > 1970 {
            for y in 1970..self.year {
                if Self::is_leap_year_inner(y) {
                    days += 1;
                }
            }
        } else if self.year < 1970 {
            for y in self.year..1970 {
                if Self::is_leap_year_inner(y) {
                    days -= 1;
                }
            }
        }

        // Add the days from the start of the year up to the given date (day_of_year is 1‑based)
        days += (self.day_of_year()? - 1) as i64;

        // Convert days to seconds and add the time of day
        Ok(days * 86400
            + (self.hour as i64) * 3600
            + (self.minute as i64) * 60
            + (self.second as i64))
    }
}

#[derive(Debug, Clone, Copy)]
pub enum TimeError {
    InvalidYear,
    InvalidMonth,
    InvalidDay,
    InvalidHour,
    InvalidMinute,
    InvalidSecond,
}
