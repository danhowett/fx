//! Shared time conversions used across parsers.
//!
//! Windows artefacts overwhelmingly use FILETIME (100-nanosecond intervals
//! since 1601-01-01 UTC). Several parsers need to convert it, so it lives here
//! once rather than being re-implemented (and re-bugged) per parser.

use time::OffsetDateTime;

/// Difference between the FILETIME epoch (1601-01-01) and the Unix epoch
/// (1970-01-01), in 100-nanosecond intervals.
const FILETIME_UNIX_DIFF_100NS: u64 = 116_444_736_000_000_000;

/// Convert a Windows FILETIME (`u64`, 100ns since 1601-01-01 UTC) to an
/// `OffsetDateTime`. Returns `None` for 0 (the conventional "unset" value) or
/// on overflow / pre-1970 values.
pub fn filetime_to_datetime(ft: u64) -> Option<OffsetDateTime> {
    if ft == 0 || ft < FILETIME_UNIX_DIFF_100NS {
        return None;
    }
    let unix_100ns = ft - FILETIME_UNIX_DIFF_100NS;
    let unix_nanos = (unix_100ns as i128) * 100;
    OffsetDateTime::from_unix_timestamp_nanos(unix_nanos).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_filetime() {
        // 2019-01-01T00:00:00Z. FILETIME = 100ns intervals since 1601-01-01.
        let dt = filetime_to_datetime(131_907_744_000_000_000).unwrap();
        assert_eq!(dt.year(), 2019);
        assert_eq!(dt.month() as u8, 1);
        assert_eq!(dt.day(), 1);
    }

    #[test]
    fn zero_is_none() {
        assert!(filetime_to_datetime(0).is_none());
    }
}
