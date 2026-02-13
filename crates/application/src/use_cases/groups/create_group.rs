use ferrous_dns_domain::{DomainError, Group};
use std::sync::Arc;
use tracing::{info, instrument};

use crate::ports::GroupRepository;

pub struct CreateGroupUseCase {
    group_repo: Arc<dyn GroupRepository>,
}

impl CreateGroupUseCase {
    pub fn new(group_repo: Arc<dyn GroupRepository>) -> Self {
        Self { group_repo }
    }

    #[instrument(skip(self))]
    pub async fn execute(
        &self,
        name: String,
        comment: Option<String>,
    ) -> Result<Group, DomainError> {
        Group::validate_name(&name).map_err(DomainError::InvalidGroupName)?;
        Group::validate_comment(&comment.as_ref().map(|s| Arc::from(s.as_str())))
            .map_err(DomainError::InvalidGroupName)?;

        let group = self.group_repo.create(name.clone(), comment).await?;

        info!(
            group_id = ?group.id,
            name = %name,
            "Group created successfully"
        );

        Ok(group)
    }
}
