// SPDX-License-Identifier: LGPL-2.1-or-later
//! Conversion between Unix time and FAT timestamps.
//!
//! FAT stores local time with no time zone information. For reproducible
//! images we always treat on-disk timestamps as UTC, which is also what
//! systemd does when it drives mtools (TZ=UTC) and what the kernel does with
//! the tz=UTC mount option.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// A FAT timestamp: a date word, a time word and the creation-time
/// hundredths field.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FatTimestamp {
    /// Day (bits 0-4), month (bits 5-8), years since 1980 (bits 9-15).
    pub date: u16,
    /// Two-second count (bits 0-4), minutes (bits 5-10), hours (bits 11-15).
    pub time: u16,
    /// Hundredths of a second in the range 0..=199, only stored for the
    /// creation time. The name is the one the specification gives the field
    /// (DIR_CrtTimeTenth).
    pub tenths: u8,
}

/// Seconds between the Unix epoch and 1980-01-01T00:00:00Z.
pub const FAT_EPOCH: i64 = 315_532_800;
/// The second of the last representable instant: 2107-12-31T23:59:59Z,
/// with the hundredths field covering up to .99 of it. That is the limit
/// of the creation time; a modification time, stored in two second steps,
/// ends one second earlier, which is also where Linux puts its s_time_max.
pub const FAT_MAX: i64 = 4_354_819_199;
/// The largest nanosecond value representable in the last second.
pub const FAT_MAX_NANOS: u32 = 990_000_000;

impl FatTimestamp {
    /// The earliest FAT timestamp, 1980-01-01 00:00:00.
    pub const EPOCH: FatTimestamp = FatTimestamp {
        date: 1 | (1 << 5),
        time: 0,
        tenths: 0,
    };

    /// Converts a Unix time, interpreted as UTC, into a FAT timestamp.
    /// Times outside the representable range are clamped.
    pub fn from_unix(secs: i64, nanos: u32) -> FatTimestamp {
        let (secs, nanos) = if secs < FAT_EPOCH {
            (FAT_EPOCH, 0)
        } else if secs > FAT_MAX || (secs == FAT_MAX && nanos > FAT_MAX_NANOS) {
            (FAT_MAX, FAT_MAX_NANOS)
        } else {
            (secs, nanos.min(999_999_999))
        };
        let days = secs.div_euclid(86_400);
        let sod = secs.rem_euclid(86_400) as u32;
        let (year, month, day) = civil_from_days(days);
        let hour = sod / 3600;
        let minute = (sod % 3600) / 60;
        let second = sod % 60;
        FatTimestamp {
            date: (((year - 1980) as u16) << 9) | ((month as u16) << 5) | day as u16,
            time: ((hour as u16) << 11) | ((minute as u16) << 5) | (second / 2) as u16,
            tenths: ((second % 2) * 100 + nanos / 10_000_000) as u8,
        }
    }

    /// Converts a FAT timestamp into Unix seconds and nanoseconds, treating it
    /// as UTC, with the arithmetic of the Linux driver (fs/fat/misc.c,
    /// fat_time_fat2unix()), so that fields out of range decode to the same
    /// instant here and there: a month of 0 counts as January and 13 to 15
    /// as January too, a day of 0 as the 1st, hours, minutes and seconds
    /// beyond their range carry over, and hundredths above 199 add whole
    /// seconds.
    pub fn to_unix(self) -> (i64, u32) {
        // Days before the first of each month in a non-leap year, indexed by
        // month; 13 to 15 fall into the zero padding.
        const DAYS_BEFORE_MONTH: [i64; 16] = [0, 0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334, 0, 0, 0];
        // 1970-01-01 to 1980-01-01.
        const DAYS_DELTA: i64 = 3652;
        // Years since 1980; 2100 is not a leap year.
        const YEAR_2100: i64 = 120;
        let year = i64::from(self.years_since_1980());
        let month = i64::from(self.month()).max(1);
        let day = i64::from(self.day()).max(1) - 1;
        let mut leap_days = (year + 3) / 4;
        if year > YEAR_2100 {
            leap_days -= 1;
        }
        if year & 3 == 0 && year != YEAR_2100 && month > 2 {
            leap_days += 1;
        }
        let days = year * 365 + leap_days + DAYS_BEFORE_MONTH[month as usize] + day + DAYS_DELTA;
        let secs = days * 86_400
            + i64::from(self.hours()) * 3600
            + i64::from(self.minutes()) * 60
            + i64::from(self.two_seconds()) * 2;
        let hundredths = u32::from(self.tenths);
        (secs + i64::from(hundredths / 100), (hundredths % 100) * 10_000_000)
    }

    /// Returns just the date part, with the time zeroed. Used for the access
    /// date field.
    #[must_use]
    pub fn date_only(self) -> FatTimestamp {
        FatTimestamp {
            date: self.date,
            time: 0,
            tenths: 0,
        }
    }

    /// The years since 1980, bits 9 to 15 of the date.
    pub fn years_since_1980(self) -> u16 {
        self.date >> 9
    }

    /// The month, bits 5 to 8 of the date: 1 to 12 in a valid date.
    pub fn month(self) -> u16 {
        (self.date >> 5) & 0x0f
    }

    /// The day of the month, bits 0 to 4 of the date: 1 or more in a valid
    /// date.
    pub fn day(self) -> u16 {
        self.date & 0x1f
    }

    /// The hours, bits 11 to 15 of the time: 0 to 23 in a valid time.
    pub fn hours(self) -> u16 {
        self.time >> 11
    }

    /// The minutes, bits 5 to 10 of the time: 0 to 59 in a valid time.
    pub fn minutes(self) -> u16 {
        (self.time >> 5) & 0x3f
    }

    /// The seconds in two second steps, bits 0 to 4 of the time: 0 to 29 in
    /// a valid time.
    pub fn two_seconds(self) -> u16 {
        self.time & 0x1f
    }

    /// Whether the date names a day of a month. A day beyond the end of its
    /// month still counts, as the readers roll it over.
    pub fn date_is_valid(self) -> bool {
        (1..=12).contains(&self.month()) && self.day() != 0
    }

    /// Whether the time names a time of the day.
    pub fn time_is_valid(self) -> bool {
        self.hours() <= 23 && self.minutes() <= 59 && self.two_seconds() <= 29
    }

    /// Converts a system time, clamping to the representable range.
    pub fn from_system_time(t: SystemTime) -> FatTimestamp {
        match t.duration_since(UNIX_EPOCH) {
            Ok(d) => FatTimestamp::from_unix(i64::try_from(d.as_secs()).unwrap_or(i64::MAX), d.subsec_nanos()),
            Err(e) => FatTimestamp::from_unix(-i64::try_from(e.duration().as_secs()).unwrap_or(i64::MAX), 0),
        }
    }

    /// The instant as a system time.
    pub fn to_system_time(self) -> SystemTime {
        let (secs, nanos) = self.to_unix();
        // FAT times start in 1980.
        UNIX_EPOCH + Duration::new(u64::try_from(secs).unwrap_or(0), nanos)
    }
}

/// Converts a proleptic Gregorian date into days since 1970-01-01.
pub fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = i64::from(if month > 2 { month - 3 } else { month + 9 });
    let doy = (153 * mp + 2) / 5 + i64::from(day) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Converts days since 1970-01-01 into a proleptic Gregorian date.
pub fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

/// Converts a system time to microseconds since the epoch, saturating at
/// both ends.
pub fn to_usec(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_micros()).unwrap_or(u64::MAX))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch() {
        assert_eq!(FatTimestamp::from_unix(FAT_EPOCH, 0), FatTimestamp::EPOCH);
        assert_eq!(FatTimestamp::from_unix(0, 0), FatTimestamp::EPOCH);
        assert_eq!(FatTimestamp::EPOCH.to_unix(), (FAT_EPOCH, 0));
    }

    #[test]
    fn known_values() {
        // 2015-03-14T09:26:53Z, the timestamp mkfs.fat --invariant uses.
        let t = FatTimestamp::from_unix(1_426_325_213, 0);
        assert_eq!(t.date, ((2015 - 1980) << 9) | (3 << 5) | 14);
        assert_eq!(t.time, (9 << 11) | (26 << 5) | (53 / 2));
        assert_eq!(t.tenths, 100);
        assert_eq!(t.to_unix(), (1_426_325_213, 0));
    }

    #[test]
    fn round_trip_and_clamp() {
        for secs in (FAT_EPOCH..FAT_MAX).step_by(86_400 * 37 + 7_919) {
            let t = FatTimestamp::from_unix(secs, 123_456_789);
            let (back, nanos) = t.to_unix();
            assert_eq!(back, secs, "secs {}", secs);
            assert_eq!(nanos, 120_000_000);
        }
        let t = FatTimestamp::from_unix(FAT_MAX + 1_000_000, 0);
        assert_eq!(t.to_unix(), (FAT_MAX, FAT_MAX_NANOS));
        assert_eq!(t.tenths, 199);
        let t = FatTimestamp::from_unix(FAT_MAX, 0);
        assert_eq!(t.date, ((2107 - 1980) << 9) | (12 << 5) | 31);
        assert_eq!(t.to_unix(), (FAT_MAX, 0));
        // Every encodable timestamp survives a round trip, the last one too.
        let last = FatTimestamp {
            date: 0xFF9F,
            time: 0xBF7D,
            tenths: 199,
        };
        let (s, n) = last.to_unix();
        assert_eq!(FatTimestamp::from_unix(s, n), last);
    }

    #[test]
    fn civil() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(days_from_civil(2000, 3, 1), 11_017);
        assert_eq!(civil_from_days(11_017), (2000, 3, 1));
        assert_eq!(civil_from_days(-1), (1969, 12, 31));
        for d in (-800_000..800_000).step_by(997) {
            let (y, m, day) = civil_from_days(d);
            assert_eq!(days_from_civil(y, m, day), d);
        }
    }
}
