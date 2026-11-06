use crate::DERError;

/// A point in time, in seconds since the Unix epoch (UTC).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Time {
    pub seconds: i64,
}

impl Time {
    /// Decodes a UTCTime in the form DER requires, `YYMMDDHHMMSSZ` (X.690 11.8). As RFC 5280
    /// 4.1.2.5.1 specifies, years 50 to 99 are 1950 to 1999 and 00 to 49 are 2000 to 2049.
    pub fn from_utc_time(contents: &[u8]) -> Result<Time, DERError> {
        let digits = Time::digits(contents, 12)?;
        let year = digits[0] * 10 + digits[1];
        let year = if year >= 50 { 1900 + year } else { 2000 + year };
        Time::from_fields(year, &digits[2..])
    }

    /// Decodes a GeneralizedTime in the form DER requires, `YYYYMMDDHHMMSSZ` without fractions
    /// (X.690 11.7, RFC 5280 4.1.2.5.2).
    pub fn from_generalized_time(contents: &[u8]) -> Result<Time, DERError> {
        let digits = Time::digits(contents, 14)?;
        let year = digits[0] * 1000 + digits[1] * 100 + digits[2] * 10 + digits[3];
        Time::from_fields(year, &digits[4..])
    }

    fn digits(contents: &[u8], count: usize) -> Result<Vec<i64>, DERError> {
        if contents.len() != count + 1 || contents[count] != b'Z' || !contents[..count].iter().all(u8::is_ascii_digit) {
            return Err(DERError::InvalidValue("a time is not in the form DER requires"));
        }
        Ok(contents[..count].iter().map(|digit| i64::from(digit - b'0')).collect())
    }

    /// `fields` holds two digits each of month, day, hour, minute and second.
    fn from_fields(year: i64, fields: &[i64]) -> Result<Time, DERError> {
        let pair = |index: usize| fields[index * 2] * 10 + fields[index * 2 + 1];
        let (month, day, hour, minute, second) = (pair(0), pair(1), pair(2), pair(3), pair(4));
        if !(1..=12).contains(&month) || day < 1 || day > Time::days_in_month(year, month) || hour > 23 || minute > 59 || second > 59 {
            return Err(DERError::InvalidValue("a time is out of range"));
        }
        Ok(Time { seconds: Time::days_from_civil(year, month, day) * 86_400 + hour * 3_600 + minute * 60 + second })
    }

    pub fn is_leap_year(year: i64) -> bool {
        (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
    }

    pub fn days_in_month(year: i64, month: i64) -> i64 {
        match month {
            2 if Time::is_leap_year(year) => 29,
            2 => 28,
            4 | 6 | 9 | 11 => 30,
            _ => 31,
        }
    }

    /// The number of days from 1970-01-01 to the given date of the proleptic Gregorian calendar.
    pub fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
        let year = if month <= 2 { year - 1 } else { year };
        let era = year.div_euclid(400);
        let year_of_era = year - era * 400;
        let month_index = (month + 9) % 12;
        let day_of_year = (153 * month_index + 2) / 5 + day - 1;
        let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
        era * 146_097 + day_of_era - 719_468
    }

    /// The date `(year, month, day)` of a number of days since 1970-01-01.
    pub fn civil_from_days(days: i64) -> (i64, i64, i64) {
        let days = days + 719_468;
        let era = days.div_euclid(146_097);
        let day_of_era = days - era * 146_097;
        let year_of_era = (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
        let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
        let month_index = (5 * day_of_year + 2) / 153;
        let day = day_of_year - (153 * month_index + 2) / 5 + 1;
        let month = if month_index < 10 { month_index + 3 } else { month_index - 9 };
        let year = year_of_era + era * 400 + i64::from(month <= 2);
        (year, month, day)
    }
}
