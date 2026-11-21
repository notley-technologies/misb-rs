//! MISP time (MISB ST 0603.5) and its conversion to and from UTC.
//!
//! The MISP Time System counts SI seconds since 1970-01-01T00:00:00 with no
//! leap seconds: MISP time = TAI - 8.000082 s exactly (ST 0603.5 section 6,
//! R-ST1402TIME-52). ST 0601 tag 2 is a MISP time in microseconds, so it is
//! neither UTC nor POSIX time; since 2017-01-01 it reads 28.999918 s ahead
//! of UTC. [`MispTime`] is the type for producing it correctly, and
//! [`LeapSeconds`] is the table the conversion needs (Motion Imagery
//! Handbook Table 17: MISP = ComputeTAI(UTC) - MEpoch, with MEpoch =
//! 1970-01-01T00:00:08.000082 TAI).
//!
//! The library never reads the system clock: callers pass the time in, for
//! example with [`MispTime::from_system_time`].
//!
//! ```
//! use misb::{LeapSeconds, MispTime, UtcDateTime};
//!
//! // The Motion Imagery Handbook's reference vector (R-ST1402TIME-61).
//! let utc: UtcDateTime = "2022-07-12T09:05:03.000700Z".parse().unwrap();
//! let t = MispTime::from_utc(utc, LeapSeconds::builtin()).unwrap();
//! assert_eq!(t.as_micros(), 1_657_616_732_000_618);
//! assert_eq!(t.to_utc(LeapSeconds::builtin()), Some(utc));
//! ```

use std::fmt;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

const US: i64 = 1_000_000;
const US_PER_DAY: i64 = 86_400 * US;
/// MEpoch - MISP epoch: 8.000082 s (ST 0603.5 section 6), in microseconds.
const MISP_TAI_OFFSET_US: i64 = 8_000_082;
/// 1972-01-01T00:00:00 UTC as a POSIX count, where the leap second era
/// begins (TAI - UTC = 10 s exactly).
const UTC_1972: i64 = 63_072_000;

/// A MISP time: microseconds since 1970-01-01T00:00:00 on the MISP time
/// scale (MISB ST 0603.5), the value of ST 0601 tags 2 and 72.
///
/// It is a plain linear count (R-ST1402TIME-51): adding a duration is
/// exact, and there is no leap second to skip or repeat.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
pub struct MispTime(u64);

impl MispTime {
    /// The MISP epoch, 1970-01-01T00:00:00 MISP (= UTC at that instant).
    pub const EPOCH: MispTime = MispTime(0);

    /// A MISP time from its microsecond count.
    #[must_use]
    pub const fn from_micros(us: u64) -> MispTime {
        MispTime(us)
    }

    /// The microsecond count (the ST 0601 tag 2 value).
    #[must_use]
    pub const fn as_micros(self) -> u64 {
        self.0
    }

    /// The MISP time of a UTC instant. `None` before 1970-01-01, at a
    /// 23:59:60 that is not a leap second in `table`, at a second a
    /// negative leap second removed, or past the range of a `u64`.
    ///
    /// Before 1972 UTC ran at a rate offset from TAI; the conversion uses
    /// the last rule of Motion Imagery Handbook Table 15 for 1968-02-01 to
    /// 1972-01-01 (TAI - UTC = 4.2131700 s + (MJD - 39126) x 0.002592 s),
    /// to within a microsecond.
    #[must_use]
    pub fn from_utc(utc: UtcDateTime, table: &LeapSeconds) -> Option<MispTime> {
        let day = days_from_civil(utc.year, utc.month, utc.day);
        let secs_of_day = i64::from(utc.hour) * 3600 + i64::from(utc.minute) * 60 + i64::from(utc.second);
        // POSIX count of the reading; 23:59:60 lands on the next 00:00:00.
        let posix_s = day.checked_mul(86_400)?.checked_add(secs_of_day)?;
        let posix_us = posix_s.checked_mul(US)?.checked_add(i64::from(utc.micros))?;
        if posix_us < 0 {
            return None;
        }
        if posix_s < UTC_1972 {
            if utc.second == 60 {
                return None;
            }
            return u64::try_from(pre_1972_misp(posix_us)).ok().map(MispTime);
        }
        // The offset in force during the second: for 23:59:60 that is the
        // offset of 23:59:59, as the new one applies from 00:00:00.
        let offset = if utc.second == 60 {
            let before = table.offset_at(posix_s - 1);
            if table.offset_at(posix_s) != before + 1 || utc.hour != 23 || utc.minute != 59 {
                return None;
            }
            before
        } else {
            let offset = table.offset_at(posix_s);
            // A negative leap second removes 23:59:59 before an effect date.
            if utc.second == 59 && utc.hour == 23 && utc.minute == 59 && table.offset_at(posix_s + 1) == offset - 1 {
                return None;
            }
            offset
        };
        let misp = posix_us.checked_add(i64::from(offset) * US)?.checked_sub(MISP_TAI_OFFSET_US)?;
        u64::try_from(misp).ok().map(MispTime)
    }

    /// The UTC reading of this MISP time; 23:59:60 during an inserted leap
    /// second. `None` for the 0.107758 s that UTC skipped at
    /// 1972-01-01T00:00:00 when it moved to whole leap seconds.
    #[must_use]
    pub fn to_utc(self, table: &LeapSeconds) -> Option<UtcDateTime> {
        let misp = i64::try_from(self.0).ok()?;
        // Try each table era from the newest: the reading under that era's
        // offset must fall inside the era, or be its leap second.
        let eras = table.entries();
        for (i, &(start, offset)) in eras.iter().enumerate().rev() {
            let posix_us = misp.checked_add(MISP_TAI_OFFSET_US)?.checked_sub(i64::from(offset) * US)?;
            if posix_us < start * US {
                continue;
            }
            match eras.get(i + 1) {
                Some(&(next, next_offset)) if posix_us >= next * US => {
                    // Past the end of this era under its own offset: only an
                    // inserted second (offset rising by one) fits.
                    if next_offset == offset + 1 && posix_us < (next + 1) * US {
                        let mut t = UtcDateTime::from_posix_micros(posix_us - US)?;
                        t.second = 60;
                        return Some(t);
                    }
                    return None;
                }
                _ => return UtcDateTime::from_posix_micros(posix_us),
            }
        }
        // Before 1972: invert the rate rule. MISP times between the end of
        // that rule and the first leap second era are the skipped 0.107758 s.
        let posix_us = pre_1972_posix(misp);
        if posix_us < UTC_1972 * US {
            UtcDateTime::from_posix_micros(posix_us)
        } else {
            None
        }
    }

    /// The MISP time of a POSIX UTC count in microseconds (as `SystemTime`
    /// and most clocks give it). A POSIX count cannot name an inserted leap
    /// second (R-ST1402TIME-60): during one it repeats the following
    /// second, so two MISP times map to the same count; this returns the
    /// later one.
    #[must_use]
    pub fn from_posix_utc_micros(us: i64, table: &LeapSeconds) -> Option<MispTime> {
        MispTime::from_utc(UtcDateTime::from_posix_micros(us)?, table)
    }

    /// The MISP time of a `SystemTime`, which counts POSIX UTC (see
    /// [`MispTime::from_posix_utc_micros`]).
    #[must_use]
    pub fn from_system_time(t: SystemTime, table: &LeapSeconds) -> Option<MispTime> {
        let us = t.duration_since(UNIX_EPOCH).ok()?.as_micros();
        MispTime::from_posix_utc_micros(i64::try_from(us).ok()?, table)
    }

    /// Treat a POSIX time count as if it were MISP time, with no offset.
    ///
    /// This is **not** conformant (MISP time is TAI - 8.000082 s, about 29
    /// s ahead of UTC since 2017), but many deployed encoders write POSIX
    /// time into tag 2, and a system that must match them can say so
    /// explicitly with this instead of by accident.
    #[must_use]
    pub const fn from_posix_assuming_no_offset(posix_us: u64) -> MispTime {
        MispTime(posix_us)
    }

    /// `self + us`, or `None` on overflow.
    #[must_use]
    pub fn checked_add_micros(self, us: i64) -> Option<MispTime> {
        if us >= 0 {
            self.0.checked_add(us as u64).map(MispTime)
        } else {
            self.0.checked_sub(us.unsigned_abs()).map(MispTime)
        }
    }
}

impl From<MispTime> for u64 {
    fn from(t: MispTime) -> u64 {
        t.0
    }
}

impl fmt::Display for MispTime {
    /// The calendar reading of the count on 86,400-second days, labelled
    /// `MISP` (the format of [`crate::Value::Time`]), e.g.
    /// `2022-07-12T09:05:32.000618 MISP`. Not a UTC reading.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&crate::Value::Time(self.0), f)
    }
}

/// MISP time of a POSIX count before 1972 (Handbook Table 15, last row):
/// TAI - UTC = 4.2131700 + (MJD - 39126) x 0.002592 s, which is exactly
/// 8.000082 s at 1970-01-01 (MJD 40587), so MISP = POSIX x (1 + 0.002592 /
/// 86400) with no constant term. Rounded to the nearest microsecond.
fn pre_1972_misp(posix_us: i64) -> i64 {
    let p = i128::from(posix_us);
    let num: i128 = 86_400_002_592;
    let den: i128 = 86_400_000_000;
    ((p * num + den / 2) / den) as i64
}

/// Inverse of [`pre_1972_misp`].
fn pre_1972_posix(misp_us: i64) -> i64 {
    let m = i128::from(misp_us);
    let num: i128 = 86_400_000_000;
    let den: i128 = 86_400_002_592;
    ((m * num + den / 2) / den) as i64
}

/// A table of TAI - UTC offsets: the leap seconds.
///
/// [`LeapSeconds::builtin`] lists every leap second from 1972 to the date of
/// this release; [`LeapSeconds::from_list`] builds a newer one, for example
/// from the IERS `leap-seconds.list`. Conversions for instants at or after
/// [`LeapSeconds::valid_until`] use the last offset: if a leap second has
/// been announced since, they are a second off until the table is updated.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LeapSeconds {
    /// (POSIX second the offset takes effect, TAI - UTC in seconds), from
    /// 1972-01-01, strictly increasing in time.
    entries: Vec<(i64, i32)>,
    valid_until: i64,
}

/// TAI - UTC from 1972 (IERS Bulletin C; the Motion Imagery Handbook Table
/// 15 lists the same through 2017-01-01). POSIX seconds of each effect date.
const BUILTIN: [(i64, i32); 28] = [
    (63_072_000, 10),    // 1972-01-01
    (78_796_800, 11),    // 1972-07-01
    (94_694_400, 12),    // 1973-01-01
    (126_230_400, 13),   // 1974-01-01
    (157_766_400, 14),   // 1975-01-01
    (189_302_400, 15),   // 1976-01-01
    (220_924_800, 16),   // 1977-01-01
    (252_460_800, 17),   // 1978-01-01
    (283_996_800, 18),   // 1979-01-01
    (315_532_800, 19),   // 1980-01-01
    (362_793_600, 20),   // 1981-07-01
    (394_329_600, 21),   // 1982-07-01
    (425_865_600, 22),   // 1983-07-01
    (489_024_000, 23),   // 1985-07-01
    (567_993_600, 24),   // 1988-01-01
    (631_152_000, 25),   // 1990-01-01
    (662_688_000, 26),   // 1991-01-01
    (709_948_800, 27),   // 1992-07-01
    (741_484_800, 28),   // 1993-07-01
    (773_020_800, 29),   // 1994-07-01
    (820_454_400, 30),   // 1996-01-01
    (867_715_200, 31),   // 1997-07-01
    (915_148_800, 32),   // 1999-01-01
    (1_136_073_600, 33), // 2006-01-01
    (1_230_768_000, 34), // 2009-01-01
    (1_341_100_800, 35), // 2012-07-01
    (1_435_708_800, 36), // 2015-07-01
    (1_483_228_800, 37), // 2017-01-01
];

/// IERS Bulletin C 72 (6 July 2026) announced no leap second at the end of
/// December 2026, so the table holds until the next possible insertion,
/// 2027-06-30T23:59:60: valid before 2027-07-01T00:00:00 UTC.
const BUILTIN_VALID_UNTIL: i64 = 1_814_400_000;

/// Errors from [`LeapSeconds::from_list`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum LeapSecondsError {
    /// The list is empty.
    Empty,
    /// The first entry is not 1972-01-01 with TAI - UTC = 10 s.
    BadStart,
    /// Dates are not strictly increasing, or an offset changes by other
    /// than one second.
    BadStep,
    /// `valid_until` is before the last entry.
    BadExpiry,
}

impl fmt::Display for LeapSecondsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            LeapSecondsError::Empty => "leap second list is empty",
            LeapSecondsError::BadStart => "leap second list must start at 1972-01-01 with 10 s",
            LeapSecondsError::BadStep => "leap second dates must increase and offsets change by one second",
            LeapSecondsError::BadExpiry => "leap second list expires before its last entry",
        })
    }
}

impl std::error::Error for LeapSecondsError {}

impl LeapSeconds {
    /// The table shipped with this release, valid before
    /// 2027-07-01T00:00:00 UTC (IERS Bulletin C 72).
    #[must_use]
    pub fn builtin() -> &'static LeapSeconds {
        use std::sync::OnceLock;
        static TABLE: OnceLock<LeapSeconds> = OnceLock::new();
        TABLE.get_or_init(|| LeapSeconds { entries: BUILTIN.to_vec(), valid_until: BUILTIN_VALID_UNTIL })
    }

    /// A table from `(POSIX second of effect, TAI - UTC in seconds)`
    /// entries, the first being `(63072000, 10)` (1972-01-01), and the
    /// POSIX second before which it is known to hold.
    pub fn from_list(entries: &[(i64, i32)], valid_until: i64) -> Result<LeapSeconds, LeapSecondsError> {
        let (&first, rest) = entries.split_first().ok_or(LeapSecondsError::Empty)?;
        if first != (UTC_1972, 10) {
            return Err(LeapSecondsError::BadStart);
        }
        let mut prev = first;
        for &e in rest {
            if e.0 <= prev.0 || (e.1 - prev.1).abs() != 1 {
                return Err(LeapSecondsError::BadStep);
            }
            prev = e;
        }
        if valid_until < prev.0 {
            return Err(LeapSecondsError::BadExpiry);
        }
        Ok(LeapSeconds { entries: entries.to_vec(), valid_until })
    }

    /// The entries, oldest first.
    #[must_use]
    pub fn entries(&self) -> &[(i64, i32)] {
        &self.entries
    }

    /// The POSIX second before which the table is known to be complete.
    #[must_use]
    pub fn valid_until(&self) -> i64 {
        self.valid_until
    }

    /// TAI - UTC in whole seconds at a POSIX second from 1972 on.
    #[must_use]
    pub fn offset_at(&self, posix_s: i64) -> i32 {
        let i = self.entries.partition_point(|&(start, _)| start <= posix_s);
        self.entries.get(i.saturating_sub(1)).map_or(10, |&(_, offset)| offset)
    }

    /// The value of ST 0601 tag 136 (Leap Seconds) at a POSIX second:
    /// `round(TAI - UTC - 8.000082 s)` (DECISIONS X-5), 29 since 2017.
    #[must_use]
    pub fn st0601_leap_seconds(&self, posix_s: i64) -> i32 {
        // TAI - UTC is whole seconds from 1972, so this is TAI - UTC - 8.
        self.offset_at(posix_s) - 8
    }
}

/// A UTC calendar reading, with a seconds field that can be 60 during an
/// inserted leap second.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UtcDateTime {
    /// Year, 1970 or later for conversions.
    pub year: i32,
    /// Month, 1 to 12.
    pub month: u8,
    /// Day of the month, 1 to 31.
    pub day: u8,
    /// Hour, 0 to 23.
    pub hour: u8,
    /// Minute, 0 to 59.
    pub minute: u8,
    /// Second, 0 to 60 (60 only during a leap second).
    pub second: u8,
    /// Microseconds, 0 to 999,999.
    pub micros: u32,
}

impl UtcDateTime {
    /// A reading, checked for a real calendar date and field ranges
    /// (`second` may be 60; whether it is a leap second depends on the
    /// table, checked by [`MispTime::from_utc`]).
    #[must_use]
    pub fn new(year: i32, month: u8, day: u8, hour: u8, minute: u8, second: u8, micros: u32) -> Option<UtcDateTime> {
        let ok = (1..=12).contains(&month)
            && day >= 1
            && day <= days_in_month(year, month)
            && hour < 24
            && minute < 60
            && second <= 60
            && micros < 1_000_000;
        ok.then_some(UtcDateTime { year, month, day, hour, minute, second, micros })
    }

    /// The reading of a POSIX microsecond count (never second 60).
    #[must_use]
    pub fn from_posix_micros(us: i64) -> Option<UtcDateTime> {
        let days = us.div_euclid(US_PER_DAY);
        let rem = us.rem_euclid(US_PER_DAY);
        let (year, month, day) = civil_from_days(days)?;
        let secs = rem / US;
        Some(UtcDateTime {
            year,
            month,
            day,
            hour: (secs / 3600) as u8,
            minute: (secs / 60 % 60) as u8,
            second: (secs % 60) as u8,
            micros: (rem % US) as u32,
        })
    }
}

impl fmt::Display for UtcDateTime {
    /// RFC 3339 with microseconds, e.g. `2016-12-31T23:59:60.500000Z`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:06}Z",
            self.year, self.month, self.day, self.hour, self.minute, self.second, self.micros
        )
    }
}

/// Error parsing a [`UtcDateTime`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParseUtcError;

impl fmt::Display for ParseUtcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("expected YYYY-MM-DDThh:mm:ss[.f...]Z")
    }
}

impl std::error::Error for ParseUtcError {}

impl FromStr for UtcDateTime {
    type Err = ParseUtcError;

    /// `YYYY-MM-DDThh:mm:ss[.f...]Z` (RFC 3339 in UTC; `t` and `z` accepted,
    /// up to 9 fraction digits, truncated to microseconds).
    fn from_str(s: &str) -> Result<UtcDateTime, ParseUtcError> {
        let b = s.as_bytes();
        let num = |r: std::ops::Range<usize>| -> Result<u32, ParseUtcError> {
            let part = b.get(r).ok_or(ParseUtcError)?;
            if part.is_empty() || !part.iter().all(u8::is_ascii_digit) {
                return Err(ParseUtcError);
            }
            Ok(part.iter().fold(0u32, |v, d| v * 10 + u32::from(d - b'0')))
        };
        let sep = |i: usize, c: &[u8]| b.get(i).map_or(false, |x| c.contains(x));
        if b.len() < 20 || !sep(4, b"-") || !sep(7, b"-") || !sep(10, b"Tt") || !sep(13, b":") || !sep(16, b":") {
            return Err(ParseUtcError);
        }
        let mut micros = 0u32;
        let mut i = 19;
        if sep(19, b".") {
            let start = 20;
            let mut end = start;
            while b.get(end).map_or(false, u8::is_ascii_digit) {
                end += 1;
            }
            if end == start || end - start > 9 {
                return Err(ParseUtcError);
            }
            let digits = &b[start..end.min(start + 6)];
            micros = digits.iter().fold(0u32, |v, d| v * 10 + u32::from(d - b'0'));
            micros *= 10u32.pow(6 - digits.len() as u32);
            i = end;
        }
        if i + 1 != b.len() || !sep(i, b"Zz") {
            return Err(ParseUtcError);
        }
        let year = i32::try_from(num(0..4)?).map_err(|_| ParseUtcError)?;
        UtcDateTime::new(
            year,
            num(5..7)? as u8,
            num(8..10)? as u8,
            num(11..13)? as u8,
            num(14..16)? as u8,
            num(17..19)? as u8,
            micros,
        )
        .ok_or(ParseUtcError)
    }
}

fn is_leap_year(y: i32) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

fn days_in_month(y: i32, m: u8) -> u8 {
    match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(y) => 29,
        2 => 28,
        _ => 0,
    }
}

/// Days since 1970-01-01 of a proleptic Gregorian date (H. Hinnant's
/// `days_from_civil`).
fn days_from_civil(y: i32, m: u8, d: u8) -> i64 {
    let y = i64::from(y) - i64::from(m <= 2);
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let m = i64::from(m);
    let mp = if m > 2 { m - 3 } else { m + 9 };
    let doy = (153 * mp + 2) / 5 + i64::from(d) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Inverse of [`days_from_civil`]; `None` past the range of `i32` years.
fn civil_from_days(days: i64) -> Option<(i32, u8, u8)> {
    let z = days.checked_add(719_468)?;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    Some((i32::try_from(y).ok()?, m as u8, d as u8))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utc(s: &str) -> UtcDateTime {
        s.parse().unwrap()
    }

    fn misp(s: &str) -> u64 {
        MispTime::from_utc(utc(s), LeapSeconds::builtin()).unwrap().as_micros()
    }

    #[test]
    fn handbook_reference_vector() {
        // R-ST1402TIME-61: UTC 2022-07-12T09:05:03.000700Z, TAI - UTC = 37.
        assert_eq!(misp("2022-07-12T09:05:03.000700Z"), 1_657_616_732_000_618);
        assert_eq!(MispTime::from_micros(1_657_616_732_000_618).to_string(), "2022-07-12T09:05:32.000618 MISP");
    }

    #[test]
    fn epoch_and_pre_1972() {
        // MEpoch was chosen so that MISP = UTC at 1970-01-01.
        assert_eq!(misp("1970-01-01T00:00:00Z"), 0);
        // Rate offset: +3e-8, about 0.95 s after one year.
        assert_eq!(misp("1971-01-01T00:00:00Z"), 31_536_000_000_000 + 946_080);
        assert!(MispTime::from_utc(utc("1969-12-31T23:59:59Z"), LeapSeconds::builtin()).is_none());
        // Round trip within the rate era.
        let t = MispTime::from_micros(31_536_000_946_080);
        assert_eq!(t.to_utc(LeapSeconds::builtin()), Some(utc("1971-01-01T00:00:00Z")));
    }

    #[test]
    fn first_leap_era() {
        // 1972-01-01T00:00:00 UTC = TAI 1972-01-01T00:00:10.
        assert_eq!(misp("1972-01-01T00:00:00Z") as i64, UTC_1972 * US + 10 * US - MISP_TAI_OFFSET_US);
        // The 0.107758 s UTC skipped there has no reading.
        let gap = MispTime::from_micros((UTC_1972 * US + 10 * US - MISP_TAI_OFFSET_US) as u64 - 50_000);
        assert_eq!(gap.to_utc(LeapSeconds::builtin()), None);
    }

    #[test]
    fn leap_second_2016() {
        let before = misp("2016-12-31T23:59:59.000000Z");
        let leap = misp("2016-12-31T23:59:60.500000Z");
        let after = misp("2017-01-01T00:00:00.000000Z");
        assert_eq!(leap - before, 1_500_000);
        assert_eq!(after - before, 2_000_000);
        let table = LeapSeconds::builtin();
        assert_eq!(MispTime::from_micros(leap).to_utc(table), Some(utc("2016-12-31T23:59:60.500000Z")));
        assert_eq!(MispTime::from_micros(after).to_utc(table), Some(utc("2017-01-01T00:00:00Z")));
        // Not a leap second day.
        assert!(MispTime::from_utc(utc("2017-12-31T23:59:60Z"), table).is_none());
        assert_eq!(table.st0601_leap_seconds(1_700_000_000), 29);
    }

    #[test]
    fn every_leap_second_round_trips() {
        let table = LeapSeconds::builtin();
        for w in table.entries().windows(2) {
            let effect = w[1].0;
            for us in [-1_500_000i64, -1, 0, 1, 999_999] {
                let posix = effect * US + us;
                let t = MispTime::from_posix_utc_micros(posix, table).unwrap();
                let back = t.to_utc(table).unwrap();
                assert_eq!(MispTime::from_utc(back, table), Some(t));
            }
            let mut leap = UtcDateTime::from_posix_micros((effect - 1) * US + 250_000).unwrap();
            leap.second = 60;
            let t = MispTime::from_utc(leap, table).unwrap();
            assert_eq!(t.to_utc(table), Some(leap));
        }
    }

    #[test]
    fn parse_and_print() {
        let t = utc("2016-12-31T23:59:60.5Z");
        assert_eq!(t.micros, 500_000);
        assert_eq!(t.to_string(), "2016-12-31T23:59:60.500000Z");
        assert_eq!(utc("2024-02-29t01:02:03.123456789z").micros, 123_456);
        for bad in ["2023-02-29T00:00:00Z", "2024-01-01 00:00:00Z", "2024-01-01T00:00:00", "2024-13-01T00:00:00Z"] {
            assert!(bad.parse::<UtcDateTime>().is_err(), "{bad}");
        }
    }

    #[test]
    fn custom_table() {
        assert_eq!(LeapSeconds::from_list(&[], 0), Err(LeapSecondsError::Empty));
        assert_eq!(LeapSeconds::from_list(&[(0, 10)], 0), Err(LeapSecondsError::BadStart));
        let t = LeapSeconds::from_list(&BUILTIN, BUILTIN_VALID_UNTIL).unwrap();
        assert_eq!(&t, LeapSeconds::builtin());
        // A hypothetical leap second at 2030-01-01.
        let mut list = BUILTIN.to_vec();
        list.push((1_893_456_000, 38));
        let t = LeapSeconds::from_list(&list, 1_900_000_000).unwrap();
        assert_eq!(t.offset_at(1_893_456_000), 38);
        assert_eq!(BUILTIN_VALID_UNTIL, days_from_civil(2027, 7, 1) * 86_400);
        for &(s, _) in &BUILTIN[..1] {
            assert_eq!(s, days_from_civil(1972, 1, 1) * 86_400);
        }
    }
}
