use async_trait::async_trait;
use ferrous_dns_domain::{DomainAction, DomainError, ManagedDomain};
use std::time::Duration;

/// Fields to change on a managed domain; `None` keeps the stored value, and
/// `comment: Some(None)` clears it.
#[derive(Debug, Clone, Default)]
pub struct ManagedDomainUpdate {
    pub name: Option<String>,
    pub domain: Option<String>,
    pub action: Option<DomainAction>,
    pub group_id: Option<i64>,
    pub comment: Option<Option<String>>,
    pub enabled: Option<bool>,
}

/// A managed domain to create.
#[derive(Debug, Clone)]
pub struct NewManagedDomain {
    pub name: String,
    pub domain: String,
    pub action: DomainAction,
    pub group_id: i64,
    pub comment: Option<String>,
    pub enabled: bool,
    /// Expires the rule that long after it is created; `None` keeps it until
    /// it is deleted.
    pub expires_in: Option<Duration>,
}

/// A managed domain to create in a batch. `fallback_name` is tried when the
/// group already has a rule named `rule.name`.
#[derive(Debug, Clone)]
pub struct BulkManagedDomain {
    pub rule: NewManagedDomain,
    pub fallback_name: Option<String>,
}

/// What became of one [`BulkManagedDomain`].
#[derive(Debug, Clone)]
pub enum CreateManyOutcome {
    Created(ManagedDomain),
    /// The group already has a permanent rule for the domain with the same
    /// action and enabled state, other than a blocked service's rule.
    AlreadyPresent,
    /// The group already has a rule under each name.
    NameTaken,
}

#[async_trait]
pub trait ManagedDomainRepository: Send + Sync {
    async fn create(&self, new: NewManagedDomain) -> Result<ManagedDomain, DomainError>;

    /// Creates the rules in one transaction, and returns each one's outcome at
    /// its index. A rule the batch already created counts as present.
    async fn create_many(
        &self,
        entries: Vec<BulkManagedDomain>,
    ) -> Result<Vec<CreateManyOutcome>, DomainError>;

    async fn get_by_id(&self, id: i64) -> Result<Option<ManagedDomain>, DomainError>;

    async fn get_all(&self) -> Result<Vec<ManagedDomain>, DomainError>;

    /// One page sorted by name, then group. `search` keeps only the domains whose
    /// name or domain contains it, ignoring ASCII case; the total counts those.
    async fn get_all_paged(
        &self,
        limit: u32,
        offset: u32,
        search: Option<&str>,
    ) -> Result<(Vec<ManagedDomain>, u64), DomainError>;

    async fn update(
        &self,
        id: i64,
        update: ManagedDomainUpdate,
    ) -> Result<ManagedDomain, DomainError>;

    async fn delete(&self, id: i64) -> Result<(), DomainError>;

    /// Deletes every rule whose expiry has passed and returns how many.
    async fn delete_expired(&self) -> Result<u64, DomainError>;

    async fn bulk_create_for_service(
        &self,
        service_id: &str,
        group_id: i64,
        domains: Vec<(String, String)>,
    ) -> Result<usize, DomainError>;

    async fn delete_by_service(&self, service_id: &str, group_id: i64) -> Result<u64, DomainError>;

    async fn delete_all_by_service(&self, service_id: &str) -> Result<u64, DomainError>;
}
