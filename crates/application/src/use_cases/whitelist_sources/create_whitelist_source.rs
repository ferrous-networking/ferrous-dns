use ferrous_dns_domain::{DomainError, WhitelistSource};
use std::sync::Arc;
use tracing::{info, instrument};

use crate::ports::{GroupRepository, WhitelistSourceRepository};

pub struct CreateWhitelistSourceUseCase {
    repo: Arc<dyn WhitelistSourceRepository>,
    group_repo: Arc<dyn GroupRepository>,
}

impl CreateWhitelistSourceUseCase {
    pub fn new(
        repo: Arc<dyn WhitelistSourceRepository>,
        group_repo: Arc<dyn GroupRepository>,
    ) -> Self {
        Self { repo, group_repo }
    }

    #[instrument(skip(self))]
    pub async fn execute(
        &self,
        name: String,
        url: Option<String>,
        group_id: i64,
        comment: Option<String>,
        enabled: bool,
    ) -> Result<WhitelistSource, DomainError> {
        WhitelistSource::validate_name(&name).map_err(DomainError::InvalidWhitelistSource)?;

        WhitelistSource::validate_url(&url.as_deref().map(Arc::from))
            .map_err(DomainError::InvalidWhitelistSource)?;

        WhitelistSource::validate_comment(&comment.as_deref().map(Arc::from))
            .map_err(DomainError::InvalidWhitelistSource)?;

        self.group_repo
            .get_by_id(group_id)
            .await?
            .ok_or_else(|| DomainError::GroupNotFound(format!("Group {} not found", group_id)))?;

        let source = self
            .repo
            .create(name.clone(), url, group_id, comment, enabled)
            .await?;

        info!(
            source_id = ?source.id,
            name = %name,
            group_id = group_id,
            "Whitelist source created successfully"
        );

        Ok(source)
    }
}
