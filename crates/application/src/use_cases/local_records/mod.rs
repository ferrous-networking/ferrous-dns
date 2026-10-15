pub mod create;
pub mod delete;
pub mod update;

pub use create::CreateLocalRecordUseCase;
pub use delete::DeleteLocalRecordUseCase;
pub use update::UpdateLocalRecordUseCase;

use std::sync::Arc;

use ferrous_dns_domain::{DomainError, LocalDnsRecord, RecordType};

use crate::ports::{DnsCachePort, PtrRecordRegistry, WildcardRecordRegistry};

/// Rejects a record the resolver could not serve as written. Needs the
/// configured `local_domain`, which is what anchors a domain-less wildcard.
fn validate(record: &LocalDnsRecord, local_domain: Option<&str>) -> Result<(), DomainError> {
    LocalDnsRecord::validate_hostname(&record.hostname).map_err(DomainError::InvalidDomainName)?;
    if let Some(domain) = &record.domain {
        LocalDnsRecord::validate_domain(domain).map_err(DomainError::InvalidDomainName)?;
    }
    LocalDnsRecord::validate_address(record.record_type, record.ip)
        .map_err(DomainError::InvalidIpAddress)?;

    if record.is_wildcard() && record.wildcard_suffix(local_domain).is_none() {
        return Err(DomainError::InvalidDomainName(
            "A wildcard record needs a domain to anchor it: set the domain field or dns.local_domain".to_string(),
        ));
    }
    Ok(())
}

fn record_not_found(id: i64) -> DomainError {
    DomainError::NotFound(format!("Record with id {} not found", id))
}

fn save_failed(e: DomainError) -> DomainError {
    DomainError::IoError(format!("Failed to save configuration: {}", e))
}

/// Live DNS state mirroring the persisted records, so edits apply without a restart.
///
/// A wildcard lives only in the wildcard index (cache keys match exactly, so a
/// `*.example.com` entry there would be dead weight); an exact record lives in
/// the PTR map and the DNS cache.
#[derive(Default)]
struct LiveRecordSinks {
    ptr: Option<Arc<dyn PtrRecordRegistry>>,
    cache: Option<Arc<dyn DnsCachePort>>,
    wildcard: Option<Arc<dyn WildcardRecordRegistry>>,
}

impl LiveRecordSinks {
    /// Points every live entry keyed by `changed` — its address for PTR, its
    /// name and type for the cache and the wildcard index — at whichever of
    /// `records` now holds that key, or drops the entry when none does.
    ///
    /// Records may share a key, so a deleted or edited record cannot simply
    /// take its entries with it. The last holder wins, as at startup.
    fn refresh(
        &self,
        changed: &LocalDnsRecord,
        records: &[LocalDnsRecord],
        local_domain: Option<&str>,
    ) {
        let fqdn = changed.fqdn(local_domain);
        let same_name = |r: &&LocalDnsRecord| {
            r.record_type == changed.record_type && r.has_fqdn(&fqdn, local_domain)
        };

        if changed.is_wildcard() {
            // An unanchored wildcard is never indexed, so it has no entry to refresh.
            if let (Some(registry), Some(suffix)) =
                (&self.wildcard, changed.wildcard_suffix(local_domain))
            {
                match records.iter().rev().find(same_name) {
                    Some(owner) => registry.register(
                        &suffix,
                        owner.record_type,
                        owner.ip,
                        owner.ttl_or_default(),
                    ),
                    None => registry.unregister(&suffix, changed.record_type),
                }
            }
            return;
        }

        if let Some(registry) = &self.ptr {
            match records
                .iter()
                .rev()
                .find(|r| !r.is_wildcard() && r.ip == changed.ip)
            {
                Some(owner) => registry.register(
                    changed.ip,
                    Arc::from(owner.fqdn(local_domain)),
                    owner.ttl_or_default(),
                ),
                None => registry.unregister(changed.ip),
            }
        }

        if let Some(cache) = &self.cache {
            let record_type = RecordType::from(changed.record_type);
            // Removing first also retires the old answer from every thread's L1.
            cache.remove_record(&fqdn, &record_type, None);
            if let Some(owner) = records.iter().rev().find(same_name) {
                cache.insert_permanent_record(
                    &fqdn,
                    record_type,
                    vec![owner.ip],
                    owner.ttl_or_default(),
                );
            }
        }
    }
}
