//! Keeps the addresses of upstreams given by hostname current. Each such
//! server has one pending lookup, due when its answer's TTL runs out or, while
//! its lookups fail, on a backoff. A reload arms the servers it brings.

use super::pool::{PoolManager, Resolution};
use std::collections::HashMap;
use std::sync::{Arc, Weak};
use std::time::Duration;
use tokio::time::Instant;

/// When an upstream hostname is looked up again.
#[derive(Debug, Clone, Copy)]
pub struct HostnameRefreshTimes {
    /// The bounds an answer's TTL is held to: a very short one would look the
    /// name up every few seconds, a very long one would follow a move only
    /// after hours. The task never sleeps longer than `max_ttl`, so it notices
    /// a dropped pool manager.
    pub min_ttl: Duration,
    pub max_ttl: Duration,
    /// How long an answer from the system resolver, which reports no TTL, is
    /// kept.
    pub without_ttl: Duration,
    /// The wait after a failed lookup, doubling with each further failure up
    /// to `max_retry`.
    pub retry: Duration,
    pub max_retry: Duration,
}

impl HostnameRefreshTimes {
    /// How long until a server is looked up again, after a lookup that found
    /// `resolution` and `failures` failed lookups in a row. `None` for a server
    /// given by address.
    pub fn next_lookup_in(&self, resolution: Resolution, failures: u32) -> Option<Duration> {
        match resolution {
            Resolution::Literal => None,
            Resolution::Resolved { ttl: Some(ttl) } => {
                Some(Duration::from_secs(ttl.into()).clamp(self.min_ttl, self.max_ttl))
            }
            Resolution::Resolved { ttl: None } => Some(self.without_ttl),
            Resolution::Failed => {
                let doublings = failures.saturating_sub(1).min(31);
                Some(
                    self.retry
                        .saturating_mul(1 << doublings)
                        .min(self.max_retry),
                )
            }
        }
    }
}

struct PendingLookup {
    at: Instant,
    failures: u32,
}

/// Looks each upstream hostname of `pool_manager` up again when it falls
/// due. Runs until the pool manager is dropped.
pub async fn run_hostname_refresh(pool_manager: Weak<PoolManager>, times: HostnameRefreshTimes) {
    let Some(reloaded) = pool_manager.upgrade().map(|pm| pm.reloaded()) else {
        return;
    };
    let mut pending: HashMap<Arc<str>, PendingLookup> = HashMap::new();
    loop {
        let Some(pm) = pool_manager.upgrade() else {
            return;
        };
        arm(&mut pending, pm.hostname_servers(), &times);
        drop(pm);

        let longest = Instant::now() + times.max_ttl;
        let wake = pending
            .values()
            .map(|lookup| lookup.at)
            .min()
            .map_or(longest, |at| at.min(longest));
        tokio::select! {
            () = tokio::time::sleep_until(wake) => {}
            () = reloaded.notified() => {
                // A reload looked every server up again: schedule them all
                // by what it found, failures included.
                pending.clear();
                continue;
            }
        }

        let Some(pm) = pool_manager.upgrade() else {
            return;
        };
        let now = Instant::now();
        let due: Vec<Arc<str>> = pending
            .iter()
            .filter(|(_, lookup)| lookup.at <= now)
            .map(|(original, _)| Arc::clone(original))
            .collect();
        for original in due {
            let resolution = pm.refresh_hostname(&original).await;
            let Some(lookup) = pending.get_mut(&original) else {
                continue;
            };
            // `None`: a reload took the server away while it was looked up.
            let next_in = resolution.and_then(|resolution| {
                lookup.failures = match resolution {
                    Resolution::Failed => lookup.failures + 1,
                    _ => 0,
                };
                times.next_lookup_in(resolution, lookup.failures)
            });
            match next_in {
                Some(wait) => lookup.at = Instant::now() + wait,
                None => {
                    pending.remove(&original);
                }
            }
        }
    }
}

/// Arms the servers in `live` that have no pending lookup yet, from what
/// their last lookup found, and drops the ones no pool lists any more.
fn arm(
    pending: &mut HashMap<Arc<str>, PendingLookup>,
    live: Vec<(Arc<str>, Resolution)>,
    times: &HostnameRefreshTimes,
) {
    pending.retain(|original, _| live.iter().any(|(server, _)| server == original));
    let now = Instant::now();
    for (original, resolution) in live {
        if pending.contains_key(&original) {
            continue;
        }
        let failures = u32::from(resolution == Resolution::Failed);
        if let Some(wait) = times.next_lookup_in(resolution, failures) {
            pending.insert(
                original,
                PendingLookup {
                    at: now + wait,
                    failures,
                },
            );
        }
    }
}
