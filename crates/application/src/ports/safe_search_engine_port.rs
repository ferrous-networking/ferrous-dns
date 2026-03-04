use async_trait::async_trait;
use ferrous_dns_domain::DomainError;

/// Hot-path port for Safe Search enforcement.
///
/// Implementors hold a precompiled index (`ArcSwap`) mapping search engine
/// domains to their Safe Search CNAME targets, keyed by group configuration.
#[async_trait]
pub trait SafeSearchEnginePort: Send + Sync {
    /// Returns the CNAME target to resolve when Safe Search is active for
    /// `domain` in the given `group_id`. Returns `None` if Safe Search is
    /// disabled or the domain is not a known search engine domain.
    fn cname_for(&self, domain: &str, group_id: i64) -> Option<&'static str>;

    /// Reloads the Safe Search index from the repository.
    async fn reload(&self) -> Result<(), DomainError>;
}
