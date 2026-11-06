use std::fmt;

use der::Time;

/// A security patch date, `YYYY-MM-DD`, as Android writes `ro.build.version.security_patch`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PatchDate {
    pub year: u16,
    pub month: u8,
    pub day: u8,
}

impl PatchDate {
    pub fn parse(text: &str) -> Option<PatchDate> {
        let bytes = text.as_bytes();
        if bytes.len() != 10 || bytes[4] != b'-' || bytes[7] != b'-' {
            return None;
        }
        let number = |range: std::ops::Range<usize>| -> Option<u16> {
            let part = &text[range];
            if part.bytes().all(|byte| byte.is_ascii_digit()) { part.parse().ok() } else { None }
        };
        let (year, month, day) = (number(0..4)?, number(5..7)?, number(8..10)?);
        if !(1..=12).contains(&month) || day < 1 || i64::from(day) > Time::days_in_month(i64::from(year), i64::from(month)) {
            return None;
        }
        Some(PatchDate { year, month: month as u8, day: day as u8 })
    }

    /// The patch level of the operating system in attestation, `YYYYMM`.
    pub fn os_patch_level(&self) -> u64 {
        u64::from(self.year) * 100 + u64::from(self.month)
    }

    /// The patch levels of the vendor and boot images in attestation, `YYYYMMDD`.
    pub fn long_patch_level(&self) -> u64 {
        self.os_patch_level() * 100 + u64::from(self.day)
    }

    /// The start of the day, in seconds since the Unix epoch (UTC).
    pub fn seconds(&self) -> i64 {
        Time::days_from_civil(i64::from(self.year), i64::from(self.month), i64::from(self.day)) * 86_400
    }
}

impl fmt::Display for PatchDate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:04}-{:02}-{:02}", self.year, self.month, self.day)
    }
}
