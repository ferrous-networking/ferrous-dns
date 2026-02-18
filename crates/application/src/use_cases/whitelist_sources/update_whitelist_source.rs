use ferrous_dns_domain::{DomainError, WhitelistSource};
use std::sync::Arc;
use tracing::{info, instrument};

use crate::ports::{GroupRepository, WhitelistSourceRepository};

pub struct UpdateWhitelistSourceUseCase {
    repo: Arc<dyn WhitelistSourceRepository>,
    group_repo: Arc<dyn GroupRepository>,
}

impl UpdateWhitelistSourceUseCase {
    pub fn new(
        repo: Arc<dyn WhitelistSourceRepository>,
        group_repo: Arc<dyn GroupRepository>,
    ) -> Self {
        Self { repo, group_repo }
    }

    #[instrument(skip(self))]
    pub async fn execute(
        &self,
        id: i64,
        name: Option<String>,
        url: Option<Option<String>>,
        group_id: Option<i64>,
        comment: Option<String>,
        enabled: Option<bool>,
    ) -> Result<WhitelistSource, DomainError> {
        self.repo.get_by_id(id).await?.ok_or_else(|| {
            DomainError::WhitelistSourceNotFound(format!("Whitelist source {} not found", id))
        })?;

        if let Some(ref n) = name {
            WhitelistSource::validate_name(n).map_err(DomainError::InvalidWhitelistSource)?;
        }

        if let Some(ref u_opt) = url {
            WhitelistSource::validate_url(&u_opt.as_deref().map(Arc::from))
                .map_err(DomainError::InvalidWhitelistSource)?;
        }

        if let Some(ref c) = comment {
            WhitelistSource::validate_comment(&Some(Arc::from(c.as_str())))
                .map_err(DomainError::InvalidWhitelistSource)?;
        }

        if let Some(gid) = group_id {
            self.group_repo
                .get_by_id(gid)
                .await?
                .ok_or_else(|| DomainError::GroupNotFound(format!("Group {} not found", gid)))?;
        }

        let updated = self
            .repo
            .update(id, name, url, group_id, comment, enabled)
            .await?;

        info!(
            source_id = ?id,
            name = %updated.name,
            enabled = %updated.enabled,
            "Whitelist source updated successfully"
        );

        Ok(updated)
    }
}
