use ferrous_dns_domain::{DomainError, ScheduleProfile, TimeSlot};
use std::sync::Arc;
use tracing::instrument;

use crate::ports::ScheduleProfileRepository;

/// Retrieves schedule profiles and their time slots.
pub struct GetScheduleProfilesUseCase {
    repo: Arc<dyn ScheduleProfileRepository>,
}

impl GetScheduleProfilesUseCase {
    /// Creates a new `GetScheduleProfilesUseCase`.
    pub fn new(repo: Arc<dyn ScheduleProfileRepository>) -> Self {
        Self { repo }
    }

    /// Returns all schedule profiles ordered by name.
    #[instrument(skip(self))]
    pub async fn get_all(&self) -> Result<Vec<ScheduleProfile>, DomainError> {
        self.repo.get_all().await
    }

    /// Returns the profile with the given id.
    ///
    /// Returns [`DomainError::ScheduleProfileNotFound`] if it does not exist.
    #[instrument(skip(self))]
    pub async fn get_by_id(&self, id: i64) -> Result<ScheduleProfile, DomainError> {
        self.repo
            .get_by_id(id)
            .await?
            .ok_or(DomainError::ScheduleProfileNotFound(id))
    }

    /// Returns all time slots for the given profile.
    ///
    /// Returns [`DomainError::ScheduleProfileNotFound`] if the profile does not exist.
    #[instrument(skip(self))]
    pub async fn get_slots(&self, profile_id: i64) -> Result<Vec<TimeSlot>, DomainError> {
        self.repo
            .get_by_id(profile_id)
            .await?
            .ok_or(DomainError::ScheduleProfileNotFound(profile_id))?;
        self.repo.get_slots(profile_id).await
    }

    /// Returns the profile id assigned to a group, or `None` if unassigned.
    #[instrument(skip(self))]
    pub async fn get_group_assignment(&self, group_id: i64) -> Result<Option<i64>, DomainError> {
        self.repo.get_group_assignment(group_id).await
    }
}
