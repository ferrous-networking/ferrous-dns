use ferrous_dns_domain::{DomainError, ScheduleAction, TimeSlot};
use std::sync::Arc;
use tracing::{info, instrument};

use crate::ports::ScheduleProfileRepository;

pub struct ManageTimeSlotsUseCase {
    repo: Arc<dyn ScheduleProfileRepository>,
}

impl ManageTimeSlotsUseCase {
    pub fn new(repo: Arc<dyn ScheduleProfileRepository>) -> Self {
        Self { repo }
    }

    #[instrument(skip(self))]
    pub async fn add_slot(
        &self,
        profile_id: i64,
        days: u8,
        start_time: String,
        end_time: String,
        action: ScheduleAction,
    ) -> Result<TimeSlot, DomainError> {
        self.repo
            .get_by_id(profile_id)
            .await?
            .ok_or(DomainError::ScheduleProfileNotFound(profile_id))?;

        TimeSlot::validate_days(days).map_err(DomainError::InvalidTimeSlot)?;
        TimeSlot::validate_time_format(&start_time).map_err(DomainError::InvalidTimeSlot)?;
        TimeSlot::validate_time_format(&end_time).map_err(DomainError::InvalidTimeSlot)?;
        TimeSlot::validate_time_range(&start_time, &end_time)
            .map_err(DomainError::InvalidTimeSlot)?;

        let slot = self
            .repo
            .add_slot(profile_id, days, start_time, end_time, action)
            .await?;

        info!(
            slot_id = ?slot.id,
            profile_id = profile_id,
            action = action.to_str(),
            "Time slot added"
        );

        Ok(slot)
    }

    #[instrument(skip(self))]
    pub async fn delete_slot(&self, slot_id: i64) -> Result<(), DomainError> {
        self.repo.delete_slot(slot_id).await?;

        info!(slot_id = slot_id, "Time slot deleted");

        Ok(())
    }
}
