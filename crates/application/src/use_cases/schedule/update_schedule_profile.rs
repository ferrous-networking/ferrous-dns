use ferrous_dns_domain::{DomainError, ScheduleProfile};
use std::sync::Arc;
use tracing::{info, instrument};

use crate::ports::ScheduleProfileRepository;

pub struct UpdateScheduleProfileUseCase {
    repo: Arc<dyn ScheduleProfileRepository>,
}

impl UpdateScheduleProfileUseCase {
    pub fn new(repo: Arc<dyn ScheduleProfileRepository>) -> Self {
        Self { repo }
    }

    #[instrument(skip(self))]
    pub async fn execute(
        &self,
        id: i64,
        name: Option<String>,
        timezone: Option<String>,
        comment: Option<String>,
    ) -> Result<ScheduleProfile, DomainError> {
        self.repo
            .get_by_id(id)
            .await?
            .ok_or(DomainError::ScheduleProfileNotFound(id))?;

        if let Some(ref n) = name {
            ScheduleProfile::validate_name(n).map_err(DomainError::InvalidScheduleProfile)?;
        }
        if let Some(ref tz) = timezone {
            ScheduleProfile::validate_timezone(tz).map_err(DomainError::InvalidScheduleProfile)?;
        }

        let profile = self.repo.update(id, name, timezone, comment).await?;

        info!(profile_id = id, "Schedule profile updated");

        Ok(profile)
    }
}
