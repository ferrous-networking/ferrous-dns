use dashmap::DashMap;
use ferrous_dns_application::ports::ScheduleStatePort;
use ferrous_dns_domain::GroupOverride;
use rustc_hash::FxBuildHasher;

type Entry = (GroupOverride, Option<u64>);

pub struct ScheduleStateStore {
    overrides: DashMap<i64, Entry, FxBuildHasher>,
}

impl ScheduleStateStore {
    pub fn new() -> Self {
        Self {
            overrides: DashMap::with_hasher(FxBuildHasher),
        }
    }
}

impl Default for ScheduleStateStore {
    fn default() -> Self {
        Self::new()
    }
}

impl ScheduleStatePort for ScheduleStateStore {
    #[inline]
    fn get(&self, group_id: i64) -> Option<GroupOverride> {
        self.overrides.get(&group_id).map(|e| e.0)
    }

    fn set(&self, group_id: i64, state: GroupOverride) {
        let expiry = match state {
            GroupOverride::TimedBypassUntil(t) | GroupOverride::TimedBlockUntil(t) => Some(t),
            _ => None,
        };
        self.overrides.insert(group_id, (state, expiry));
    }

    fn clear(&self, group_id: i64) {
        self.overrides.remove(&group_id);
    }

    #[inline]
    fn is_empty(&self) -> bool {
        self.overrides.is_empty()
    }

    fn sweep_expired(&self) {
        let now = crate::dns::cache::coarse_clock::coarse_now_secs();
        self.overrides
            .retain(|_, (state, expiry)| match (state, expiry) {
                (
                    GroupOverride::TimedBypassUntil(_) | GroupOverride::TimedBlockUntil(_),
                    Some(t),
                ) => now < *t,
                _ => true,
            });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferrous_dns_application::ports::ScheduleStatePort;
    use ferrous_dns_domain::GroupOverride;

    #[test]
    fn test_set_and_get_block_all_override() {
        let store = ScheduleStateStore::new();
        store.set(1, GroupOverride::BlockAll);
        assert_eq!(store.get(1), Some(GroupOverride::BlockAll));
    }

    #[test]
    fn test_set_and_get_allow_all_override() {
        let store = ScheduleStateStore::new();
        store.set(2, GroupOverride::AllowAll);
        assert_eq!(store.get(2), Some(GroupOverride::AllowAll));
    }

    #[test]
    fn test_clear_override_removes_entry() {
        let store = ScheduleStateStore::new();
        store.set(1, GroupOverride::BlockAll);
        store.clear(1);
        assert_eq!(store.get(1), None);
    }

    #[test]
    fn test_is_empty_initial_state() {
        let store = ScheduleStateStore::new();
        assert!(store.is_empty());
    }

    #[test]
    fn test_is_empty_after_set_returns_false() {
        let store = ScheduleStateStore::new();
        store.set(1, GroupOverride::BlockAll);
        assert!(!store.is_empty());
    }

    #[test]
    fn test_sweep_expired_removes_timed_block_past_deadline() {
        let store = ScheduleStateStore::new();
        // Use timestamp 0 — already expired
        store.set(1, GroupOverride::TimedBlockUntil(0));
        store.sweep_expired();
        assert_eq!(store.get(1), None);
    }

    #[test]
    fn test_sweep_expired_keeps_active_timed_bypass() {
        let store = ScheduleStateStore::new();
        // Use u64::MAX — never expires
        store.set(1, GroupOverride::TimedBypassUntil(u64::MAX));
        store.sweep_expired();
        assert_eq!(
            store.get(1),
            Some(GroupOverride::TimedBypassUntil(u64::MAX))
        );
    }

    #[test]
    fn test_sweep_expired_does_not_touch_non_timed_overrides() {
        let store = ScheduleStateStore::new();
        store.set(1, GroupOverride::BlockAll);
        store.set(2, GroupOverride::AllowAll);
        store.sweep_expired();
        assert_eq!(store.get(1), Some(GroupOverride::BlockAll));
        assert_eq!(store.get(2), Some(GroupOverride::AllowAll));
    }
}
