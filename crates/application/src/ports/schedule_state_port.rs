use ferrous_dns_domain::GroupOverride;

pub trait ScheduleStatePort: Send + Sync {
    fn get(&self, group_id: i64) -> Option<GroupOverride>;
    fn set(&self, group_id: i64, state: GroupOverride);
    fn clear(&self, group_id: i64);
    fn is_empty(&self) -> bool;
    fn sweep_expired(&self);
}
