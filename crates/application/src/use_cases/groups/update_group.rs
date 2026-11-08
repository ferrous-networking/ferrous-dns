use super::require_group;
use ferrous_dns_domain::value_objects::validators::validate_comment;
use ferrous_dns_domain::{DomainError, Group};
use std::sync::Arc;
use tracing::{error, info, instrument};

use crate::ports::{BlockFilterEnginePort, GroupRepository, MalwareExemptionPort};

pub struct UpdateGroupUseCase {
    group_repo: Arc<dyn GroupRepository>,
    malware_exemptions: Arc<dyn MalwareExemptionPort>,
    block_filter_engine: Option<Arc<dyn BlockFilterEnginePort>>,
}

impl UpdateGroupUseCase {
    pub fn new(
        group_repo: Arc<dyn GroupRepository>,
        malware_exemptions: Arc<dyn MalwareExemptionPort>,
    ) -> Self {
        Self {
            group_repo,
            malware_exemptions,
            block_filter_engine: None,
        }
    }

    pub fn with_block_filter(
        mut self,
        block_filter_engine: Arc<dyn BlockFilterEnginePort>,
    ) -> Self {
        self.block_filter_engine = Some(block_filter_engine);
        self
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

        if enabled.is_some() {
            if let Some(ref engine) = self.block_filter_engine {
                if let Err(e) = engine.load_client_groups().await {
                    error!(error = %e, "Failed to reload client groups after group update");
                }
            }
        }

        if malware_detection_enabled.is_some() {
            if let Err(e) = self.malware_exemptions.reload().await {
                error!(error = %e, "Failed to reload malware detection exemptions after group update");
            }
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
