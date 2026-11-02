use async_trait::async_trait;
use ferrous_dns_domain::value_objects::validators::validate_comment;
use ferrous_dns_domain::{DomainError, Group};
use std::sync::Arc;
use tracing::{error, info, instrument};

use crate::ports::{GroupCreator, GroupRepository, MalwareExemptionPort};

pub struct CreateGroupUseCase {
    group_repo: Arc<dyn GroupRepository>,
    malware_exemptions: Arc<dyn MalwareExemptionPort>,
}

impl CreateGroupUseCase {
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
        name: String,
        comment: Option<String>,
        enabled: bool,
        malware_detection_enabled: bool,
    ) -> Result<Group, DomainError> {
        Group::validate_name(&name).map_err(DomainError::InvalidGroupName)?;
        validate_comment(comment.as_deref()).map_err(DomainError::InvalidGroupName)?;

        let group = self
            .group_repo
            .create(name.clone(), comment, enabled, malware_detection_enabled)
            .await?;

        if !malware_detection_enabled {
            if let Err(e) = self.malware_exemptions.reload().await {
                error!(error = %e, "Failed to reload malware detection exemptions after group creation");
            }
        }

        info!(
            group_id = ?group.id,
            name = %name,
            enabled,
            malware_detection_enabled,
            "Group created successfully"
        );

        Ok(group)
    }
}

#[async_trait]
impl GroupCreator for CreateGroupUseCase {
    async fn create_group(
        &self,
        name: String,
        comment: Option<String>,
        malware_detection_enabled: bool,
    ) -> Result<Group, DomainError> {
        // Backup snapshots carry no enabled flag; restored groups start enabled.
        self.execute(name, comment, true, malware_detection_enabled)
            .await
    }
}
