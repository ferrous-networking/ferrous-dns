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
