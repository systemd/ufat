// SPDX-License-Identifier: LGPL-2.1-or-later
//! What time a copy of a file gets, and what the tools share to handle
//! times.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Nanoseconds in a second.
pub const NSEC_PER_SEC: u64 = 1_000_000_000;
/// Microseconds in a second.
pub const USEC_PER_SEC: u64 = 1_000_000;

/// How copied files and directories get their timestamps.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimePolicy {
    /// Keep the source's modification time.
    Preserve,
    /// Stamp everything with this time.
    Fixed(SystemTime),
    /// Keep the source's modification time unless it is later than this,
    /// the SOURCE_DATE_EPOCH convention.
    Clamp(SystemTime),
}

impl TimePolicy {
    /// The time to store for a source modified at `source`.
    pub fn resolve(self, source: SystemTime) -> SystemTime {
        match self {
            TimePolicy::Preserve => source,
            TimePolicy::Fixed(t) => t,
            TimePolicy::Clamp(t) => source.min(t),
        }
    }
}

/// The current time.
pub fn now() -> SystemTime {
    SystemTime::now()
}

/// Converts microseconds since the epoch, as Varlink carries times, to a
/// system time.
pub fn from_usec(usec: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_micros(usec)
}

/// Converts a system time to microseconds since the epoch, saturating at
/// both ends.
pub fn to_usec(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_micros()).unwrap_or(u64::MAX))
}

/// The month after which a leap year has its extra day.
pub const FEBRUARY: i64 = 2;
/// The days of a year that is not a leap year.
pub const DAYS_PER_YEAR: i64 = 365;
/// The years from one leap year to the next one, which holds between 1980
/// and 2099.
pub const YEARS_PER_LEAP_YEAR: i64 = 4;
/// The years of a century, whose last year is no leap year unless it is
/// that of an era.
const YEARS_PER_CENTURY: i64 = 100;

// The proleptic Gregorian calendar repeats every 400 years, an era of
// 146097 days. The two conversions below are Howard Hinnant's
// days_from_civil() and civil_from_days()
// (https://howardhinnant.github.io/date_algorithms.html). They count the
// years of an era from March 1st, so that a leap day ends its year, and
// eras from 0000-03-01, 719468 days before 1970-01-01. The other numbers
// are the algorithms' own: (153 * mp + 2) / 5 is the day of the year of the
// first day of month mp, counted from March, and 1460, 36524 and 146096
// take the leap days out to find the year of the era.
const YEARS_PER_ERA: i64 = 400;
const DAYS_PER_ERA: i64 = 146_097;
const DAYS_TO_UNIX_EPOCH: i64 = 719_468;

/// Converts a proleptic Gregorian date into days since 1970-01-01.
pub fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let y = if i64::from(month) <= FEBRUARY { year - 1 } else { year };
    let era = y.div_euclid(YEARS_PER_ERA);
    let yoe = y.rem_euclid(YEARS_PER_ERA);
    let mp = i64::from(if month > 2 { month - 3 } else { month + 9 });
    let doy = (153 * mp + 2) / 5 + i64::from(day) - 1;
    let doe = yoe * DAYS_PER_YEAR + yoe / YEARS_PER_LEAP_YEAR - yoe / YEARS_PER_CENTURY + doy;
    era * DAYS_PER_ERA + doe - DAYS_TO_UNIX_EPOCH
}

/// Converts days since 1970-01-01 into a proleptic Gregorian date.
pub fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + DAYS_TO_UNIX_EPOCH;
    let era = z.div_euclid(DAYS_PER_ERA);
    let doe = z.rem_euclid(DAYS_PER_ERA);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / (DAYS_PER_ERA - 1)) / DAYS_PER_YEAR;
    let doy = doe - (DAYS_PER_YEAR * yoe + yoe / YEARS_PER_LEAP_YEAR - yoe / YEARS_PER_CENTURY);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * YEARS_PER_ERA + i64::from(month <= FEBRUARY);
    (year, month as u32, day)
}

#[cfg(test)]
mod tests {
    use super::*;

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
