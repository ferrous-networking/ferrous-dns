use async_trait::async_trait;
use ferrous_dns_domain::{DomainError, Group};

/// Port for creating a group during backup import.
///
/// Allows `ImportConfigUseCase` to depend on an abstraction rather than the
/// concrete `CreateGroupUseCase`, satisfying the Dependency Inversion Principle.
#[async_trait]
pub trait GroupCreator: Send + Sync {
    async fn create_group(
        &self,
        name: String,
        comment: Option<String>,
        enabled: bool,
        malware_detection_enabled: bool,
    ) -> Result<Group, DomainError>;
}
