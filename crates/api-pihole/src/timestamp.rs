use chrono::DateTime;

/// Parses a timestamp string (SQLite format or RFC 3339) into a Unix epoch.
///
/// Handles both `"2024-01-15 12:30:00"` (SQLite) and `"2024-01-15T12:30:00Z"` (RFC 3339).
/// Returns `None` if the timestamp cannot be parsed.
pub(crate) fn parse_unix_epoch(ts: &str) -> Option<i64> {
    let normalized = if ts.ends_with('Z') {
        ts.to_string()
    } else {
        format!("{}Z", ts.replace(' ', "T"))
    };
    DateTime::parse_from_rfc3339(&normalized)
        .ok()
        .map(|dt| dt.timestamp())
}
