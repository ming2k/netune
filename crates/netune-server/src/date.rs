//! The `Date` response header (RFC 9110 §6.6.1).
//!
//! Implemented against the system clock rather than pulled from a crate: a `Date` header is a
//! formatting problem, not a calendar library, and keeping the production graph free of a dependency
//! that exists to do arithmetic this small file already does is a standing rule of this workspace.
//!
//! # Why it is a module and not a function inside the connection
//!
//! Every response carries one, and every layer that can write a response (HTTP/1.1, HTTP/2) needs it.
//! A second copy would be a second clock read that could disagree with the first by a second, which is
//! visible to a cache.

use std::time::{SystemTime, UNIX_EPOCH};

/// The current time as an RFC 9110 IMF-fixdate, e.g. `Sun, 06 Nov 1994 08:49:37 GMT`.
pub(crate) fn http_date() -> String {
    format_at(SystemTime::now())
}

/// Format one instant, so the conversion is testable without controlling the clock.
fn format_at(now: SystemTime) -> String {
    const DAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let seconds = now
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);
    let days = seconds / 86_400;
    let second_of_day = seconds % 86_400;
    let hour = second_of_day / 3_600;
    let minute = (second_of_day % 3_600) / 60;
    let second = second_of_day % 60;
    // 1970-01-01 was a Thursday, which is index 0 of `DAYS`.
    let weekday = DAYS[(days % 7) as usize];
    let (year, month, day) = civil_from_days(days as i64);
    format!(
        "{weekday}, {day:02} {} {year} {hour:02}:{minute:02}:{second:02} GMT",
        MONTHS[(month - 1) as usize]
    )
}

/// Days since the Unix epoch to a civil date (Howard Hinnant's algorithm).
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let day_of_era = z - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let mp = (5 * day_of_year + 2) / 153;
    let day = (day_of_year - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if month <= 2 { year + 1 } else { year }, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn at(seconds: u64) -> String {
        format_at(UNIX_EPOCH + Duration::from_secs(seconds))
    }

    #[test]
    fn the_epoch_is_a_thursday() {
        assert_eq!(at(0), "Thu, 01 Jan 1970 00:00:00 GMT");
    }

    #[test]
    fn a_known_instant_matches_the_rfc_example() {
        // 1994-11-06 08:49:37 UTC, the example in RFC 9110 §6.6.1.
        assert_eq!(at(784_111_777), "Sun, 06 Nov 1994 08:49:37 GMT");
    }

    #[test]
    fn a_leap_day_is_formatted_correctly() {
        // 2024-02-29 12:00:00 UTC.
        assert_eq!(at(1_709_208_000), "Thu, 29 Feb 2024 12:00:00 GMT");
    }

    #[test]
    fn a_recent_instant_has_the_imf_fixdate_shape() {
        let date = http_date();
        assert_eq!(date.len(), 29, "{date}");
        assert!(date.ends_with(" GMT"), "{date}");
    }

    #[test]
    fn civil_dates_are_correct_at_known_anchors() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(11_017), (2000, 3, 1));
    }
}
