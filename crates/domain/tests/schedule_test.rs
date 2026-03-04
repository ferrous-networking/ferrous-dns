use ferrous_dns_domain::schedule::{ScheduleProfile, TimeSlot};
use std::sync::Arc;

// ============================================================================
// ScheduleProfile validation
// ============================================================================

#[test]
fn test_schedule_profile_validate_name_empty_returns_error() {
    let result = ScheduleProfile::validate_name("");
    assert!(result.is_err());
}

#[test]
fn test_schedule_profile_validate_name_valid() {
    let result = ScheduleProfile::validate_name("Kids Weeknight");
    assert!(result.is_ok());
}

#[test]
fn test_schedule_profile_validate_name_too_long_returns_error() {
    let long_name = "a".repeat(101);
    let result = ScheduleProfile::validate_name(&long_name);
    assert!(result.is_err());
}

#[test]
fn test_schedule_profile_validate_timezone_utc_is_valid() {
    let result = ScheduleProfile::validate_timezone("UTC");
    assert!(result.is_ok());
}

#[test]
fn test_schedule_profile_validate_timezone_iana_is_valid() {
    let result = ScheduleProfile::validate_timezone("America/Sao_Paulo");
    assert!(result.is_ok());
}

#[test]
fn test_schedule_profile_validate_timezone_empty_returns_error() {
    // Domain only validates empty/too-long; IANA validation is in the evaluator
    let result = ScheduleProfile::validate_timezone("");
    assert!(result.is_err());
}

#[test]
fn test_schedule_profile_validate_timezone_too_long_returns_error() {
    let long_tz = "A".repeat(65);
    let result = ScheduleProfile::validate_timezone(&long_tz);
    assert!(result.is_err());
}

#[test]
fn test_schedule_profile_validate_comment_none_is_ok() {
    let result = ScheduleProfile::validate_comment(&None);
    assert!(result.is_ok());
}

#[test]
fn test_schedule_profile_validate_comment_too_long_returns_error() {
    let long: Arc<str> = Arc::from("x".repeat(501).as_str());
    let result = ScheduleProfile::validate_comment(&Some(long));
    assert!(result.is_err());
}

// ============================================================================
// TimeSlot validation
// ============================================================================

#[test]
fn test_time_slot_validate_days_zero_returns_error() {
    let result = TimeSlot::validate_days(0);
    assert!(result.is_err());
}

#[test]
fn test_time_slot_validate_days_max_127_is_valid() {
    let result = TimeSlot::validate_days(127);
    assert!(result.is_ok());
}

#[test]
fn test_time_slot_validate_days_above_127_returns_error() {
    let result = TimeSlot::validate_days(128);
    assert!(result.is_err());
}

#[test]
fn test_time_slot_validate_time_format_hhmm_valid() {
    assert!(TimeSlot::validate_time_format("00:00").is_ok());
    assert!(TimeSlot::validate_time_format("23:59").is_ok());
    assert!(TimeSlot::validate_time_format("17:30").is_ok());
}

#[test]
fn test_time_slot_validate_time_format_invalid_returns_error() {
    assert!(TimeSlot::validate_time_format("25:00").is_err());
    assert!(TimeSlot::validate_time_format("12:60").is_err());
    assert!(TimeSlot::validate_time_format("1200").is_err());
    assert!(TimeSlot::validate_time_format("").is_err());
}

#[test]
fn test_time_slot_validate_time_range_start_before_end_is_ok() {
    let result = TimeSlot::validate_time_range("08:00", "17:00");
    assert!(result.is_ok());
}

#[test]
fn test_time_slot_validate_time_range_start_equals_end_returns_error() {
    let result = TimeSlot::validate_time_range("08:00", "08:00");
    assert!(result.is_err());
}

#[test]
fn test_time_slot_validate_time_range_start_after_end_returns_error() {
    let result = TimeSlot::validate_time_range("17:00", "08:00");
    assert!(result.is_err());
}
