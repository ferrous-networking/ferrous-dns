use async_trait::async_trait;
use ferrous_dns_domain::{BlocklistSource, DomainError, Group, LocalDnsRecord};

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
    ) -> Result<Group, DomainError>;
}

/// Port for creating a blocklist source during backup import.
#[async_trait]
pub trait BlocklistSourceCreator: Send + Sync {
    async fn create_blocklist_source(
        &self,
        name: String,
        url: Option<String>,
        group_ids: Vec<i64>,
        comment: Option<String>,
        enabled: bool,
    ) -> Result<BlocklistSource, DomainError>;
}

/// Port for creating a local DNS record during backup import.
#[async_trait]
pub trait LocalRecordCreator: Send + Sync {
    async fn create_local_record(
        &self,
        hostname: String,
        domain: Option<String>,
        ip: String,
        record_type: String,
        ttl: Option<u32>,
    ) -> Result<LocalDnsRecord, DomainError>;
}
