use async_trait::async_trait;
use ferrous_dns_domain::{DomainError, ScheduleAction, ScheduleProfile, TimeSlot};

#[async_trait]
pub trait ScheduleProfileRepository: Send + Sync {
    async fn create(
        &self,
        name: String,
        timezone: String,
        comment: Option<String>,
    ) -> Result<ScheduleProfile, DomainError>;

    async fn get_by_id(&self, id: i64) -> Result<Option<ScheduleProfile>, DomainError>;

    async fn get_all(&self) -> Result<Vec<ScheduleProfile>, DomainError>;

    async fn update(
        &self,
        id: i64,
        name: Option<String>,
        timezone: Option<String>,
        comment: Option<String>,
    ) -> Result<ScheduleProfile, DomainError>;

    async fn delete(&self, id: i64) -> Result<(), DomainError>;

    async fn get_slots(&self, profile_id: i64) -> Result<Vec<TimeSlot>, DomainError>;

    async fn add_slot(
        &self,
        profile_id: i64,
        days: u8,
        start_time: String,
        end_time: String,
        action: ScheduleAction,
    ) -> Result<TimeSlot, DomainError>;

    async fn delete_slot(&self, slot_id: i64) -> Result<(), DomainError>;

    async fn assign_to_group(&self, group_id: i64, profile_id: i64) -> Result<(), DomainError>;

    async fn unassign_from_group(&self, group_id: i64) -> Result<(), DomainError>;

    async fn get_group_assignment(&self, group_id: i64) -> Result<Option<i64>, DomainError>;

    async fn get_all_group_assignments(&self) -> Result<Vec<(i64, i64)>, DomainError>;
}
