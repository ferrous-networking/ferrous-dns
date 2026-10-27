use crate::ports::ClientRepository;
use ferrous_dns_domain::{DomainError, HostnameSource};
use lru::LruCache;
use std::net::IpAddr;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::time::Instant;
use tracing::debug;

/// How long a name goes without being written again for the same address.
/// Well under the day after which the PTR sync may take an mDNS name back,
/// so a device that keeps announcing keeps its name.
const REWRITE_AFTER: Duration = Duration::from_secs(3600);
/// How long an address that is not a client goes without being looked up again.
const RECHECK_UNKNOWN_AFTER: Duration = Duration::from_secs(300);
const REMEMBERED_ADDRESSES: NonZeroUsize = match NonZeroUsize::new(4096) {
    Some(capacity) => capacity,
    None => NonZeroUsize::MIN,
};

struct Seen {
    at: Instant,
    is_known: bool,
}

/// Names clients after the host names their devices announce over mDNS.
/// Busy networks repeat announcements every few minutes, so each name is
/// written at most once an hour per address, ignoring case. A host whose two
/// responders announce different names does not rewrite it on every packet.
pub struct RecordMdnsHostnamesUseCase {
    client_repo: Arc<dyn ClientRepository>,
    seen: Mutex<LruCache<(IpAddr, String), Seen>>,
}

impl RecordMdnsHostnamesUseCase {
    pub fn new(client_repo: Arc<dyn ClientRepository>) -> Self {
        Self {
            client_repo,
            seen: Mutex::new(LruCache::new(REMEMBERED_ADDRESSES)),
        }
    }

    /// Records the `(address, name)` pairs one announcement carried and
    /// returns how many were written. Only clients are named: an address
    /// that never queried this server is skipped, not added.
    pub async fn execute(&self, names: &[(IpAddr, Arc<str>)]) -> Result<usize, DomainError> {
        let mut seen = self.seen.lock().await;
        let mut written = 0;
        for (ip, name) in names {
            let key = (*ip, name.to_ascii_lowercase());
            let is_fresh = seen.get(&key).is_some_and(|last| {
                let wait = if last.is_known {
                    REWRITE_AFTER
                } else {
                    RECHECK_UNKNOWN_AFTER
                };
                last.at.elapsed() < wait
            });
            if is_fresh {
                continue;
            }

            let is_known = self.client_repo.get_by_ip(*ip).await?.is_some();
            if is_known {
                self.client_repo
                    .update_hostname(*ip, name.to_string(), HostnameSource::Mdns)
                    .await?;
                written += 1;
            }
            seen.put(
                key,
                Seen {
                    at: Instant::now(),
                    is_known,
                },
            );
        }
        if written > 0 {
            debug!(written, "Client names recorded from mDNS");
        }
        Ok(written)
    }
}
