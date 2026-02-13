use ferrous_dns_domain::{DomainError, Group};
use std::sync::Arc;
use tracing::{info, instrument};

use crate::ports::GroupRepository;

pub struct UpdateGroupUseCase {
    group_repo: Arc<dyn GroupRepository>,
}

impl UpdateGroupUseCase {
    pub fn new(group_repo: Arc<dyn GroupRepository>) -> Self {
        Self { group_repo }
    }

    #[instrument(skip(self))]
    pub async fn execute(
        &self,
        id: i64,
        name: Option<String>,
        enabled: Option<bool>,
        comment: Option<String>,
    ) -> Result<Group, DomainError> {
        let group = self
            .group_repo
            .get_by_id(id)
            .await?
            .ok_or(DomainError::GroupNotFound(format!(
                "Group {} not found",
                id
            )))?;

        if let Some(ref n) = name {
            Group::validate_name(n).map_err(DomainError::InvalidGroupName)?;
        }

        if let Some(ref c) = comment {
            Group::validate_comment(&Some(Arc::from(c.as_str())))
                .map_err(DomainError::InvalidGroupName)?;
        }

        if enabled == Some(false) && group.is_default {
            return Err(DomainError::ProtectedGroupCannotBeDisabled);
        }

        let updated_group = self.group_repo.update(id, name, enabled, comment).await?;

        info!(
            group_id = ?id,
            name = %updated_group.name,
            enabled = %updated_group.enabled,
            "Group updated successfully"
        );

        Ok(updated_group)
    }
}
