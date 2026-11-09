use crate::ports::{BlockFilterEnginePort, DohIdRepository, GroupRepository};
use crate::use_cases::groups::require_group;
use ferrous_dns_domain::value_objects::validators::validate_comment;
use ferrous_dns_domain::{DohId, DomainError};
use std::sync::Arc;
use tracing::{error, info, instrument};

pub struct UpdateDohIdUseCase {
    doh_id_repo: Arc<dyn DohIdRepository>,
    group_repo: Arc<dyn GroupRepository>,
    block_filter_engine: Arc<dyn BlockFilterEnginePort>,
}

impl UpdateDohIdUseCase {
    pub fn new(
        doh_id_repo: Arc<dyn DohIdRepository>,
        group_repo: Arc<dyn GroupRepository>,
        block_filter_engine: Arc<dyn BlockFilterEnginePort>,
    ) -> Self {
        Self {
            doh_id_repo,
            group_repo,
            block_filter_engine,
        }
    }

    #[instrument(skip(self))]
    pub async fn execute(
        &self,
        id: i64,
        name: String,
        client_id: Option<String>,
        group_id: i64,
        comment: Option<String>,
    ) -> Result<DohId, DomainError> {
        self.doh_id_repo
            .get_by_id(id)
            .await?
            .ok_or(DomainError::DohIdNotFound(id))?;

        let name = name.trim().to_string();
        DohId::validate_name(&name).map_err(DomainError::InvalidDohId)?;
        validate_comment(comment.as_deref()).map_err(DomainError::InvalidDohId)?;

        if let Some(ref cid) = client_id {
            DohId::validate_client_id(cid).map_err(DomainError::InvalidDohId)?;
        }

        require_group(self.group_repo.as_ref(), group_id).await?;

        let doh_id = self
            .doh_id_repo
            .update(id, name, client_id, group_id, comment)
            .await?;

        info!(
            doh_id = id,
            name = %doh_id.name,
            client_id = %doh_id.client_id,
            group_id = group_id,
            "DoH ID updated successfully"
        );

        if let Err(e) = self.block_filter_engine.load_client_groups().await {
            error!(error = %e, "Failed to reload client groups after DoH ID update");
        }

        Ok(doh_id)
    }
}
