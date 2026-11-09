use crate::ports::{BlockFilterEnginePort, DohIdRepository, GroupRepository};
use crate::use_cases::groups::require_group;
use ferrous_dns_domain::value_objects::validators::validate_comment;
use ferrous_dns_domain::{DohId, DomainError};
use ring::rand::SecureRandom;
use std::sync::Arc;
use tracing::{error, info, instrument};

fn generate_uuid_v4() -> Result<String, DomainError> {
    let mut bytes = [0u8; 16];
    ring::rand::SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| DomainError::IoError("CSPRNG fill failed".to_string()))?;

    // RFC 9562 §5.4: version 4 (0b0100) and RFC variant (0b10xx).
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;

    Ok(format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3],
        bytes[4], bytes[5],
        bytes[6], bytes[7],
        bytes[8], bytes[9],
        bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
    ))
}

pub struct CreateDohIdUseCase {
    doh_id_repo: Arc<dyn DohIdRepository>,
    group_repo: Arc<dyn GroupRepository>,
    block_filter_engine: Arc<dyn BlockFilterEnginePort>,
}

impl CreateDohIdUseCase {
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
        name: String,
        client_id: Option<String>,
        group_id: i64,
        comment: Option<String>,
    ) -> Result<DohId, DomainError> {
        let name = name.trim().to_string();
        DohId::validate_name(&name).map_err(DomainError::InvalidDohId)?;
        validate_comment(comment.as_deref()).map_err(DomainError::InvalidDohId)?;

        let resolved_client_id = match client_id {
            Some(id) => {
                DohId::validate_client_id(&id).map_err(DomainError::InvalidDohId)?;
                id
            }
            None => generate_uuid_v4()?,
        };

        require_group(self.group_repo.as_ref(), group_id).await?;

        let doh_id = self
            .doh_id_repo
            .create(name, resolved_client_id, group_id, comment)
            .await?;

        info!(
            doh_id = ?doh_id.id,
            name = %doh_id.name,
            client_id = %doh_id.client_id,
            group_id = group_id,
            "DoH ID created successfully"
        );

        if let Err(e) = self.block_filter_engine.load_client_groups().await {
            error!(error = %e, "Failed to reload client groups after DoH ID creation");
        }

        Ok(doh_id)
    }
}
