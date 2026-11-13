// SPDX-License-Identifier: LGPL-2.1-or-later
//! Conversion between Unix time and FAT timestamps.
//!
//! FAT stores local time with no time zone information. For reproducible
//! images we always treat on-disk timestamps as UTC, which is also what
//! systemd does when it drives mtools (TZ=UTC) and what the kernel does with
//! the tz=UTC mount option.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

// The conversions that are not about FAT live in the shared crate. They
// are part of this module under the names they always had.
pub use crate::times::{civil_from_days, days_from_civil, from_usec, to_usec};
use crate::times::{DAYS_PER_YEAR, FEBRUARY, YEARS_PER_LEAP_YEAR};

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

/// The year FAT dates count from.
pub const FAT_EPOCH_YEAR: i64 = 1980;
/// Seconds between the Unix epoch and 1980-01-01T00:00:00Z.
pub const FAT_EPOCH: i64 = 315_532_800;
/// The second of the last representable instant: 2107-12-31T23:59:59Z,
/// with the hundredths field covering up to .99 of it. That is the limit
/// of the creation time; a modification time, stored in two second steps,
/// ends one second earlier, which is also where Linux puts its s_time_max.
pub const FAT_MAX: i64 = 4_354_819_199;
/// The largest nanosecond value representable in the last second.
pub const FAT_MAX_NANOS: u32 = 990_000_000;

/// The units of a day.
const SECONDS_PER_MINUTE: u32 = 60;
const MINUTES_PER_HOUR: u32 = 60;
const HOURS_PER_DAY: u32 = 24;
const SECONDS_PER_HOUR: u32 = SECONDS_PER_MINUTE * MINUTES_PER_HOUR;
const SECONDS_PER_DAY: u32 = SECONDS_PER_HOUR * HOURS_PER_DAY;
/// FAT keeps the time of the day in steps of two seconds, and the creation
/// time the rest in hundredths of a second.
const SECONDS_PER_STEP: u32 = 2;
const HUNDREDTHS_PER_SECOND: u32 = 100;
const NANOS_PER_SECOND: u32 = 1_000_000_000;
const NANOS_PER_HUNDREDTH: u32 = NANOS_PER_SECOND / HUNDREDTHS_PER_SECOND;
/// The months of a year.
const MONTHS_PER_YEAR: u16 = 12;

/// A field of the date or of the time of a [`FatTimestamp`]: `width` bits
/// from bit `shift` on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BitField {
    shift: u32,
    width: u32,
}

impl BitField {
    /// The largest value the field holds.
    pub const fn max(self) -> u16 {
        (1 << self.width) - 1
    }

    /// The value of the field in `word`.
    pub const fn get(self, word: u16) -> u16 {
        (word >> self.shift) & self.max()
    }

    /// `value` in the place of the field, cut to the width of the field.
    pub const fn put(self, value: u16) -> u16 {
        (value & self.max()) << self.shift
    }
}

impl FatTimestamp {
    /// The day of the month in the date, bits 0 to 4.
    pub const DAY: BitField = BitField { shift: 0, width: 5 };
    /// The month in the date, bits 5 to 8.
    pub const MONTH: BitField = BitField { shift: 5, width: 4 };
    /// The years since [`FAT_EPOCH_YEAR`] in the date, bits 9 to 15.
    pub const YEARS: BitField = BitField { shift: 9, width: 7 };
    /// The seconds in two second steps in the time, bits 0 to 4.
    pub const TWO_SECONDS: BitField = BitField { shift: 0, width: 5 };
    /// The minutes in the time, bits 5 to 10.
    pub const MINUTES: BitField = BitField { shift: 5, width: 6 };
    /// The hours in the time, bits 11 to 15.
    pub const HOURS: BitField = BitField { shift: 11, width: 5 };

    /// The earliest FAT timestamp, 1980-01-01 00:00:00.
    pub const EPOCH: FatTimestamp = FatTimestamp {
        date: FatTimestamp::MONTH.put(1) | FatTimestamp::DAY.put(1),
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
            (secs, nanos.min(NANOS_PER_SECOND - 1))
        };
        let days = secs.div_euclid(i64::from(SECONDS_PER_DAY));
        let sod = secs.rem_euclid(i64::from(SECONDS_PER_DAY)) as u32;
        let (year, month, day) = civil_from_days(days);
        let hour = sod / SECONDS_PER_HOUR;
        let minute = (sod % SECONDS_PER_HOUR) / SECONDS_PER_MINUTE;
        let second = sod % SECONDS_PER_MINUTE;
        FatTimestamp {
            date: FatTimestamp::YEARS.put((year - FAT_EPOCH_YEAR) as u16)
                | FatTimestamp::MONTH.put(month as u16)
                | FatTimestamp::DAY.put(day as u16),
            time: FatTimestamp::HOURS.put(hour as u16)
                | FatTimestamp::MINUTES.put(minute as u16)
                | FatTimestamp::TWO_SECONDS.put((second / SECONDS_PER_STEP) as u16),
            tenths: ((second % SECONDS_PER_STEP) * HUNDREDTHS_PER_SECOND + nanos / NANOS_PER_HUNDREDTH) as u8,
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
        // The leap years since 1980 before this one: 1980 is one.
        let mut leap_days = (year + YEARS_PER_LEAP_YEAR - 1) / YEARS_PER_LEAP_YEAR;
        if year > YEAR_2100 {
            leap_days -= 1;
        }
        if year % YEARS_PER_LEAP_YEAR == 0 && year != YEAR_2100 && month > FEBRUARY {
            leap_days += 1;
        }
        let days = year * DAYS_PER_YEAR + leap_days + DAYS_BEFORE_MONTH[month as usize] + day + DAYS_DELTA;
        let secs = days * i64::from(SECONDS_PER_DAY)
            + i64::from(self.hours()) * i64::from(SECONDS_PER_HOUR)
            + i64::from(self.minutes()) * i64::from(SECONDS_PER_MINUTE)
            + i64::from(self.two_seconds()) * i64::from(SECONDS_PER_STEP);
        let hundredths = u32::from(self.tenths);
        (
            secs + i64::from(hundredths / HUNDREDTHS_PER_SECOND),
            (hundredths % HUNDREDTHS_PER_SECOND) * NANOS_PER_HUNDREDTH,
        )
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

    /// The years since 1980, [`FatTimestamp::YEARS`] of the date.
    pub fn years_since_1980(self) -> u16 {
        FatTimestamp::YEARS.get(self.date)
    }

    /// The month, [`FatTimestamp::MONTH`] of the date: 1 to 12 in a valid
    /// date.
    pub fn month(self) -> u16 {
        FatTimestamp::MONTH.get(self.date)
    }

    /// The day of the month, [`FatTimestamp::DAY`] of the date: 1 or more
    /// in a valid date.
    pub fn day(self) -> u16 {
        FatTimestamp::DAY.get(self.date)
    }

    /// The hours, [`FatTimestamp::HOURS`] of the time: 0 to 23 in a valid
    /// time.
    pub fn hours(self) -> u16 {
        FatTimestamp::HOURS.get(self.time)
    }

    /// The minutes, [`FatTimestamp::MINUTES`] of the time: 0 to 59 in a
    /// valid time.
    pub fn minutes(self) -> u16 {
        FatTimestamp::MINUTES.get(self.time)
    }

    /// The seconds in two second steps, [`FatTimestamp::TWO_SECONDS`] of the
    /// time: 0 to 29 in a valid time.
    pub fn two_seconds(self) -> u16 {
        FatTimestamp::TWO_SECONDS.get(self.time)
    }

    /// Whether the date names a day of a month. A day beyond the end of its
    /// month still counts, as the readers roll it over.
    pub fn date_is_valid(self) -> bool {
        (1..=MONTHS_PER_YEAR).contains(&self.month()) && self.day() != 0
    }

    /// Whether the time names a time of the day.
    pub fn time_is_valid(self) -> bool {
        u32::from(self.hours()) < HOURS_PER_DAY
            && u32::from(self.minutes()) < MINUTES_PER_HOUR
            && u32::from(self.two_seconds()) < SECONDS_PER_MINUTE / SECONDS_PER_STEP
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
        assert_eq!(
            t.date,
            FatTimestamp::YEARS.put((2015 - FAT_EPOCH_YEAR) as u16)
                | FatTimestamp::MONTH.put(3)
                | FatTimestamp::DAY.put(14)
        );
        assert_eq!(
            t.time,
            FatTimestamp::HOURS.put(9) | FatTimestamp::MINUTES.put(26) | FatTimestamp::TWO_SECONDS.put(53 / 2)
        );
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
        assert_eq!(
            t.date,
            FatTimestamp::YEARS.put((2107 - FAT_EPOCH_YEAR) as u16)
                | FatTimestamp::MONTH.put(12)
                | FatTimestamp::DAY.put(31)
        );
        assert_eq!(t.to_unix(), (FAT_MAX, 0));
        // Every encodable timestamp survives a round trip, the last one too:
        // 2107-12-31 23:59:58 and 1.99 s.
        let last = FatTimestamp {
            date: FatTimestamp::YEARS.put(FatTimestamp::YEARS.max())
                | FatTimestamp::MONTH.put(12)
                | FatTimestamp::DAY.put(31),
            time: FatTimestamp::HOURS.put(23) | FatTimestamp::MINUTES.put(59) | FatTimestamp::TWO_SECONDS.put(29),
            tenths: 199,
        };
        let (s, n) = last.to_unix();
        assert_eq!(FatTimestamp::from_unix(s, n), last);
    }
}
