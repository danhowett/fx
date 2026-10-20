//! Host time-zone rules, as Windows itself stores them.
//!
//! `SYSTEM\CurrentControlSet\Control\TimeZoneInformation` carries `Bias`,
//! `StandardBias`, `DaylightBias` and the two transition rules `StandardStart`
//! / `DaylightStart` (SYSTEMTIME: month, day-of-week, week-of-month 1–5 where 5
//! means "last", hour, minute). Applying those rules reproduces exactly what
//! the host's clock did, without a time-zone database:
//!
//! `UTC = local + Bias + (DaylightBias if DST is in effect else StandardBias)`
//!
//! Used to convert artefacts that log in host-local time (setupapi.dev.log,
//! TeamViewer connection logs) onto the UTC timeline, and mirrored in the GUI
//! for the optional host-local display.

use serde::{Deserialize, Serialize};
use time::{Date, Duration, Month, OffsetDateTime, PrimitiveDateTime, Time};

/// One SYSTEMTIME transition rule (year 0 = recurring every year).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Transition {
    pub year: u16,
    pub month: u8,
    pub day_of_week: u8,
    /// Week of month 1–5 (5 = last) for recurring rules; day of month otherwise.
    pub day: u8,
    pub hour: u8,
    pub minute: u8,
}

impl Transition {
    /// Decode a 16-byte SYSTEMTIME registry value.
    pub fn from_systemtime(b: &[u8]) -> Option<Self> {
        if b.len() < 16 {
            return None;
        }
        let w = |i: usize| u16::from_le_bytes([b[i * 2], b[i * 2 + 1]]);
        Some(Transition {
            year: w(0),
            month: w(1) as u8,
            day_of_week: w(2) as u8,
            day: w(3) as u8,
            hour: w(4) as u8,
            minute: w(5) as u8,
        })
    }

    /// The wall-clock moment of this transition in `year`.
    fn in_year(&self, year: i32) -> Option<PrimitiveDateTime> {
        let month = Month::try_from(self.month).ok()?;
        let date = if self.year != 0 {
            Date::from_calendar_date(year, month, self.day).ok()?
        } else {
            let first = Date::from_calendar_date(year, month, 1).ok()?;
            let target = self.day_of_week % 7; // 0 = Sunday
            let first_dow = first.weekday().number_days_from_sunday();
            let mut d = 1 + ((7 + target as i32 - first_dow as i32) % 7);
            d += 7 * (self.day.clamp(1, 5) as i32 - 1);
            let days_in = month.length(year) as i32;
            while d > days_in {
                d -= 7; // week 5 = last occurrence
            }
            Date::from_calendar_date(year, month, d as u8).ok()?
        };
        let t = Time::from_hms(self.hour.min(23), self.minute.min(59), 0).ok()?;
        Some(PrimitiveDateTime::new(date, t))
    }
}

/// A host's time-zone rule set.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct TzRule {
    pub name: Option<String>,
    /// Minutes; UTC = local + bias (+ standard/daylight bias).
    pub bias: i32,
    pub standard_bias: i32,
    pub daylight_bias: i32,
    pub standard_start: Option<Transition>,
    pub daylight_start: Option<Transition>,
}

impl TzRule {
    fn has_dst(&self) -> bool {
        matches!((self.standard_start, self.daylight_start), (Some(s), Some(d)) if s.month != 0 && d.month != 0)
    }

    /// Is DST in effect at this host-local wall-clock time?
    pub fn is_dst_local(&self, local: PrimitiveDateTime) -> bool {
        if !self.has_dst() {
            return false;
        }
        let y = local.year();
        let (Some(ds), Some(ss)) = (
            self.daylight_start.and_then(|t| t.in_year(y)),
            self.standard_start.and_then(|t| t.in_year(y)),
        ) else {
            return false;
        };
        if ds < ss {
            local >= ds && local < ss // northern hemisphere
        } else {
            !(local >= ss && local < ds) // southern hemisphere
        }
    }

    /// Minutes to add to host-local time to get UTC at that local time.
    pub fn bias_at_local(&self, local: PrimitiveDateTime) -> i32 {
        self.bias + if self.is_dst_local(local) { self.daylight_bias } else { self.standard_bias }
    }

    /// Convert a host-local wall-clock time (stored as if it were UTC) to UTC.
    pub fn local_to_utc(&self, local_as_utc: OffsetDateTime) -> OffsetDateTime {
        let local = PrimitiveDateTime::new(local_as_utc.date(), local_as_utc.time());
        local_as_utc + Duration::minutes(self.bias_at_local(local) as i64)
    }

    /// UTC offset label for a host-local time, e.g. "UTC+01:00".
    pub fn offset_label_at_local(&self, local: PrimitiveDateTime) -> String {
        let o = -self.bias_at_local(local);
        format!("UTC{}{:02}:{:02}", if o >= 0 { "+" } else { "-" }, o.abs() / 60, o.abs() % 60)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    fn uk() -> TzRule {
        // GMT Standard Time: last Sunday of March 01:00 -> BST, last Sunday of
        // October 02:00 -> GMT.
        TzRule {
            name: Some("GMT Standard Time".into()),
            bias: 0,
            standard_bias: 0,
            daylight_bias: -60,
            standard_start: Some(Transition { year: 0, month: 10, day_of_week: 0, day: 5, hour: 2, minute: 0 }),
            daylight_start: Some(Transition { year: 0, month: 3, day_of_week: 0, day: 5, hour: 1, minute: 0 }),
        }
    }

    #[test]
    fn uk_summer_and_winter() {
        let r = uk();
        assert_eq!(r.local_to_utc(datetime!(2024-07-01 12:00 UTC)), datetime!(2024-07-01 11:00 UTC));
        assert_eq!(r.local_to_utc(datetime!(2024-01-15 12:00 UTC)), datetime!(2024-01-15 12:00 UTC));
        // 2024: BST 31 Mar 01:00 -> 27 Oct 02:00
        assert_eq!(r.local_to_utc(datetime!(2024-03-31 00:59 UTC)), datetime!(2024-03-31 00:59 UTC));
        assert_eq!(r.local_to_utc(datetime!(2024-03-31 03:00 UTC)), datetime!(2024-03-31 02:00 UTC));
        assert_eq!(r.local_to_utc(datetime!(2024-10-27 03:00 UTC)), datetime!(2024-10-27 03:00 UTC));
    }

    #[test]
    fn southern_hemisphere_and_no_dst() {
        // AUS Eastern: Bias -600, DST first Sunday Oct 02:00 -> first Sunday Apr 03:00.
        let r = TzRule {
            name: None,
            bias: -600,
            standard_bias: 0,
            daylight_bias: -60,
            standard_start: Some(Transition { year: 0, month: 4, day_of_week: 0, day: 1, hour: 3, minute: 0 }),
            daylight_start: Some(Transition { year: 0, month: 10, day_of_week: 0, day: 1, hour: 2, minute: 0 }),
        };
        assert_eq!(r.local_to_utc(datetime!(2024-01-10 12:00 UTC)), datetime!(2024-01-10 01:00 UTC)); // AEDT +11
        assert_eq!(r.local_to_utc(datetime!(2024-07-10 12:00 UTC)), datetime!(2024-07-10 02:00 UTC)); // AEST +10
        let fixed = TzRule { bias: -330, ..Default::default() }; // India, no DST
        assert_eq!(fixed.local_to_utc(datetime!(2024-07-10 12:00 UTC)), datetime!(2024-07-10 06:30 UTC));
    }

    #[test]
    fn systemtime_decode() {
        let b = [0u8, 0, 3, 0, 0, 0, 5, 0, 1, 0, 0, 0, 0, 0, 0, 0];
        let t = Transition::from_systemtime(&b).unwrap();
        assert_eq!((t.month, t.day_of_week, t.day, t.hour), (3, 0, 5, 1));
    }
}
