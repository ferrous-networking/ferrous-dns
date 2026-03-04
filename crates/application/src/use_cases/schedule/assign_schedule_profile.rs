use ferrous_dns_domain::DomainError;
use std::sync::Arc;
use tracing::{info, instrument};

use crate::ports::{GroupRepository, ScheduleProfileRepository};

pub struct AssignScheduleProfileUseCase {
    repo: Arc<dyn ScheduleProfileRepository>,
    group_repo: Arc<dyn GroupRepository>,
}

impl AssignScheduleProfileUseCase {
    pub fn new(
        repo: Arc<dyn ScheduleProfileRepository>,
        group_repo: Arc<dyn GroupRepository>,
    ) -> Self {
        Self { repo, group_repo }
    }

    #[instrument(skip(self))]
    pub async fn assign(&self, group_id: i64, profile_id: i64) -> Result<(), DomainError> {
        self.group_repo
            .get_by_id(group_id)
            .await?
            .ok_or(DomainError::GroupNotFound(group_id))?;

        self.repo
            .get_by_id(profile_id)
            .await?
            .ok_or(DomainError::ScheduleProfileNotFound(profile_id))?;

        self.repo.assign_to_group(group_id, profile_id).await?;

        info!(group_id, profile_id, "Schedule profile assigned to group");

        Ok(())
    }

    #[instrument(skip(self))]
    pub async fn unassign(&self, group_id: i64) -> Result<(), DomainError> {
        self.group_repo
            .get_by_id(group_id)
            .await?
            .ok_or(DomainError::GroupNotFound(group_id))?;

        self.repo.unassign_from_group(group_id).await?;

        info!(group_id, "Schedule profile unassigned from group");

        Ok(())
    }
}
