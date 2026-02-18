pub fn parse_period(period: &str) -> Option<f32> {
    if period.is_empty() {
        return Some(24.0);
    }

    if period.len() < 2 {
        return None;
    }

    let (value_str, unit) = period.split_at(period.len() - 1);
    let num: f32 = value_str.parse().ok()?;

    if num <= 0.0 {
        return None;
    }

    match unit {
        "m" => Some(num / 60.0),
        "h" => Some(num),
        "d" => Some(num * 24.0),
        "w" => Some(num * 24.0 * 7.0),
        _ => None,
    }
}

pub fn validate_period(hours: f32) -> f32 {
    hours.min(720.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_period_minutes() {
        assert_eq!(parse_period("30m"), Some(0.5));
        assert_eq!(parse_period("60m"), Some(1.0));
        assert_eq!(parse_period("90m"), Some(1.5));
    }

    #[test]
    fn test_parse_period_hours() {
        assert_eq!(parse_period("1h"), Some(1.0));
        assert_eq!(parse_period("24h"), Some(24.0));
        assert_eq!(parse_period("48h"), Some(48.0));
    }

    #[test]
    fn test_parse_period_days() {
        assert_eq!(parse_period("1d"), Some(24.0));
        assert_eq!(parse_period("7d"), Some(168.0));
        assert_eq!(parse_period("30d"), Some(720.0));
    }

    #[test]
    fn test_parse_period_weeks() {
        assert_eq!(parse_period("1w"), Some(168.0));
        assert_eq!(parse_period("2w"), Some(336.0));
    }

    #[test]
    fn test_parse_period_empty() {
        assert_eq!(parse_period(""), Some(24.0));
    }

    #[test]
    fn test_parse_period_invalid() {
        assert_eq!(parse_period("invalid"), None);
        assert_eq!(parse_period("24x"), None);
        assert_eq!(parse_period("h"), None);
        assert_eq!(parse_period("abc123"), None);
    }

    #[test]
    fn test_parse_period_negative() {
        assert_eq!(parse_period("-24h"), None);
        assert_eq!(parse_period("0h"), None);
    }

    #[test]
    fn test_validate_period() {
        assert_eq!(validate_period(1.0), 1.0);
        assert_eq!(validate_period(24.0), 24.0);
        assert_eq!(validate_period(168.0), 168.0);
        assert_eq!(validate_period(720.0), 720.0);
        assert_eq!(validate_period(1000.0), 720.0);
        assert_eq!(validate_period(10000.0), 720.0);
    }
}
