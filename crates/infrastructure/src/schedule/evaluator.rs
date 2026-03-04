pub use ferrous_dns_domain::evaluate_slots;

#[cfg(test)]
mod tests {
    use ferrous_dns_domain::{ScheduleAction, TimeSlot};
    use std::sync::Arc;

    use super::evaluate_slots;

    fn make_slot(days: u8, start: &str, end: &str, action: ScheduleAction) -> TimeSlot {
        TimeSlot {
            id: None,
            profile_id: 1,
            days,
            start_time: Arc::from(start),
            end_time: Arc::from(end),
            action,
            created_at: None,
        }
    }

    // Helper: convert weekday index (0=Mon..6=Sun) to bitmask for evaluate_slots
    fn day(index: u8) -> u8 {
        1u8 << index
    }

    #[test]
    fn test_evaluate_slots_empty_list_returns_none() {
        assert_eq!(evaluate_slots(&[], day(0), "10:00"), None);
    }

    #[test]
    fn test_evaluate_slots_day_not_matching_returns_none() {
        // slot covers Mon only (days=0b0000001), today is Tue (day(1)=2)
        let slot = make_slot(0b0000001, "09:00", "18:00", ScheduleAction::BlockAll);
        assert_eq!(evaluate_slots(&[slot], day(1), "10:00"), None);
    }

    #[test]
    fn test_evaluate_slots_time_outside_range_returns_none() {
        // slot is 09:00–18:00 on Monday, current time is 20:00
        let slot = make_slot(0b0000001, "09:00", "18:00", ScheduleAction::BlockAll);
        assert_eq!(evaluate_slots(&[slot], day(0), "20:00"), None);
    }

    #[test]
    fn test_evaluate_slots_time_before_start_returns_none() {
        let slot = make_slot(0b1111111, "09:00", "18:00", ScheduleAction::BlockAll);
        assert_eq!(evaluate_slots(&[slot], day(2), "08:59"), None);
    }

    #[test]
    fn test_evaluate_slots_time_at_end_is_exclusive_returns_none() {
        let slot = make_slot(0b1111111, "09:00", "18:00", ScheduleAction::AllowAll);
        assert_eq!(evaluate_slots(&[slot], day(2), "18:00"), None);
    }

    #[test]
    fn test_evaluate_slots_single_block_slot_returns_block_all() {
        let slot = make_slot(0b1111111, "21:00", "23:59", ScheduleAction::BlockAll);
        assert_eq!(
            evaluate_slots(&[slot], day(3), "22:00"),
            Some(ScheduleAction::BlockAll)
        );
    }

    #[test]
    fn test_evaluate_slots_single_allow_slot_returns_allow_all() {
        let slot = make_slot(0b1111111, "17:00", "20:00", ScheduleAction::AllowAll);
        assert_eq!(
            evaluate_slots(&[slot], day(4), "18:30"),
            Some(ScheduleAction::AllowAll)
        );
    }

    #[test]
    fn test_evaluate_slots_block_wins_over_allow_on_overlap() {
        let allow = make_slot(0b1111111, "17:00", "20:00", ScheduleAction::AllowAll);
        let block = make_slot(0b1111111, "17:00", "18:00", ScheduleAction::BlockAll);
        assert_eq!(
            evaluate_slots(&[allow, block], day(0), "17:30"),
            Some(ScheduleAction::BlockAll)
        );
    }

    #[test]
    fn test_evaluate_slots_allow_only_no_conflicts_returns_allow_all() {
        let a1 = make_slot(0b0011111, "17:00", "20:00", ScheduleAction::AllowAll);
        let a2 = make_slot(0b1100000, "12:00", "22:00", ScheduleAction::AllowAll);
        // Saturday (index 5): day(5) = 0b0100000 = 32, covered by a2
        assert_eq!(
            evaluate_slots(&[a1, a2], day(5), "15:00"),
            Some(ScheduleAction::AllowAll)
        );
    }

    #[test]
    fn test_evaluate_slots_multiple_days_matches_correct_day() {
        // Mon–Fri (bits 0–4 = 0b0011111 = 31)
        let slot = make_slot(31, "08:00", "17:00", ScheduleAction::BlockAll);
        let slot2 = make_slot(31, "08:00", "17:00", ScheduleAction::BlockAll);
        // Tuesday (day(1) = 2) is in range
        assert_eq!(
            evaluate_slots(&[slot], day(1), "12:00"),
            Some(ScheduleAction::BlockAll)
        );
        // Saturday (day(5) = 32) is not covered by Mon–Fri mask
        assert_eq!(evaluate_slots(&[slot2], day(5), "12:00"), None);
    }
}
