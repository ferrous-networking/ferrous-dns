use super::require_group;
use ferrous_dns_domain::value_objects::validators::validate_comment;
use ferrous_dns_domain::{DomainError, Group};
use std::sync::Arc;
use tracing::{info, instrument};

use crate::ports::{GroupRepository, MalwareExemptionPort};

pub struct UpdateGroupUseCase {
    group_repo: Arc<dyn GroupRepository>,
    malware_exemptions: Arc<dyn MalwareExemptionPort>,
}

impl UpdateGroupUseCase {
    pub fn new(
        group_repo: Arc<dyn GroupRepository>,
        malware_exemptions: Arc<dyn MalwareExemptionPort>,
    ) -> Self {
        Self {
            group_repo,
            malware_exemptions,
        }
    }

    #[instrument(skip(self))]
    pub async fn execute(
        &self,
        id: i64,
        name: Option<String>,
        enabled: Option<bool>,
        comment: Option<String>,
        malware_detection_enabled: Option<bool>,
    ) -> Result<Group, DomainError> {
        let group = require_group(self.group_repo.as_ref(), id).await?;

        if let Some(ref n) = name {
            Group::validate_name(n).map_err(DomainError::InvalidGroupName)?;
        }

        validate_comment(comment.as_deref()).map_err(DomainError::InvalidGroupName)?;

        if enabled == Some(false) && group.is_default {
            return Err(DomainError::ProtectedGroupCannotBeDisabled);
        }

        let updated_group = self
            .group_repo
            .update(id, name, enabled, comment, malware_detection_enabled)
            .await?;

        if malware_detection_enabled.is_some() {
            self.malware_exemptions.reload().await?;
        }

        info!(
            group_id = ?id,
            name = %updated_group.name,
            enabled = %updated_group.enabled,
            malware_detection_enabled = updated_group.malware_detection_enabled,
            "Group updated successfully"
        );

        Ok(updated_group)
    }
}
