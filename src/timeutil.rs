//! UTC time helpers.
//!
//! Everything persisted or printed is UTC. `chrono` is deliberately not a
//! dependency: civil-from-days is 20 lines and this keeps the binary small.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Current wall clock time. Falls back to the epoch if the host clock is before 1970,
/// which keeps all later conversions total.
pub fn now() -> SystemTime {
    SystemTime::now()
}

/// Current wall clock time in milliseconds since the Unix epoch.
pub fn now_millis() -> i64 {
    unix_millis(now())
}

/// Milliseconds since the Unix epoch. Pre-epoch times clamp to `0`.
pub fn unix_millis(t: SystemTime) -> i64 {
    match t.duration_since(UNIX_EPOCH) {
        Ok(d) => i64::try_from(d.as_millis()).unwrap_or(i64::MAX),
        Err(_) => 0,
    }
}

/// Seconds since the Unix epoch. Pre-epoch times clamp to `0`.
pub fn unix_secs(t: SystemTime) -> i64 {
    match t.duration_since(UNIX_EPOCH) {
        Ok(d) => i64::try_from(d.as_secs()).unwrap_or(i64::MAX),
        Err(_) => 0,
    }
}

/// Inverse of [`unix_millis`].
pub fn from_unix_millis(ms: i64) -> SystemTime {
    let ms = ms.max(0) as u64;
    UNIX_EPOCH + Duration::from_millis(ms)
}

/// `YYYY-MM-DD HH:MM:SS` in UTC.
pub fn format_utc(t: SystemTime) -> String {
    let (y, mo, d, h, mi, s) = civil_from_unix(unix_secs(t));
    format!("{y:04}-{mo:02}-{d:02} {h:02}:{mi:02}:{s:02}")
}

/// `YYYY-MM-DD HH:MM:SS` in UTC, for a Unix-millisecond timestamp.
pub fn format_utc_millis(ms: i64) -> String {
    format_utc(from_unix_millis(ms))
}

/// Milliseconds between `since` and now; never negative.
pub fn elapsed_millis(since: SystemTime) -> i64 {
    match SystemTime::now().duration_since(since) {
        Ok(d) => i64::try_from(d.as_millis()).unwrap_or(i64::MAX),
        Err(_) => 0,
    }
}

fn civil_from_unix(secs: i64) -> (i64, i64, i64, i64, i64, i64) {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    (y, m, d, rem / 3_600, (rem % 3_600) / 60, rem % 60)
}

/// Howard Hinnant's `civil_from_days`, valid for the whole `i64` range we feed it.
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_formats_as_utc_zero() {
        assert_eq!(format_utc(UNIX_EPOCH), "1970-01-01 00:00:00");
    }

    #[test]
    fn known_timestamps_roundtrip() {
        let cases = [
            (0_i64, "1970-01-01 00:00:00"),
            (1_000_000_000, "2001-09-09 01:46:40"),
            (1_767_225_600, "2026-01-01 00:00:00"),
            (1_774_310_400, "2026-03-24 00:00:00"),
            (2_000_000_000, "2033-05-18 03:33:20"),
        ];
        for (ms_secs, want) in cases {
            assert_eq!(
                format_utc(from_unix_millis(ms_secs * 1000)),
                want,
                "secs={ms_secs}"
            );
        }
    }

    #[test]
    fn leap_day_and_century_rules() {
        // 2024-02-29 and 2000-02-29 exist, 1900-02-29 does not.
        assert_eq!(
            format_utc(from_unix_millis(1_709_164_800_000)),
            "2024-02-29 00:00:00"
        );
        assert_eq!(
            format_utc(from_unix_millis(951_782_400_000)),
            "2000-02-29 00:00:00"
        );
        assert_eq!(
            format_utc(from_unix_millis(951_868_800_000)),
            "2000-03-01 00:00:00"
        );
    }

    #[test]
    fn pre_epoch_clamps_instead_of_panicking() {
        let before = UNIX_EPOCH - Duration::from_secs(86_400);
        assert_eq!(unix_millis(before), 0);
        assert_eq!(format_utc(before), "1970-01-01 00:00:00");
    }

    #[test]
    fn millis_and_secs_agree() {
        let t = from_unix_millis(1_767_225_600_123);
        assert_eq!(unix_millis(t), 1_767_225_600_123);
        assert_eq!(unix_secs(t), 1_767_225_600);
    }
}
