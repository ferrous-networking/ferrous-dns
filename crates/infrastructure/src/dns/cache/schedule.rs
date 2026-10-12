//! Per-entry refresh timers.
//!
//! The cache arms a timer when it stores or renews an entry, for the second
//! that entry falls due, and the refresh worker takes timers as their second
//! comes. Nothing scans the cache to find what is due, so the cost follows the
//! work, and an entry is renewed on time whatever its TTL is relative to any
//! maintenance interval.
//!
//! A timer holds only the key. Whether it is still the live one is read off
//! the record when it fires: a record renewed or replaced since falls due
//! later, and that renewal armed its own timer.

use super::key::CacheKey;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, PoisonError};

/// How long before expiry an entry is renewed at the latest, unless that
/// would come before half its TTL (see [`refresh_due_at`]).
pub const REFRESH_LEAD_SECS: u64 = 60;

/// Shards of the [`TimerInbox`]; each thread pushes to one of them.
const INBOX_SHARDS: usize = 16;

static NEXT_INBOX_SHARD: AtomicUsize = AtomicUsize::new(0);

thread_local! {
    /// This thread's inbox shard, handed out round-robin on first use.
    static INBOX_SHARD: usize = NEXT_INBOX_SHARD.fetch_add(1, Ordering::Relaxed) % INBOX_SHARDS;
}

/// A timer on its way to the worker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScheduledRefresh {
    pub due_at_secs: u64,
    pub key: CacheKey,
    /// The one retry a renewal gets after every upstream answered SERVFAIL.
    pub retry: bool,
}

/// The second an entry inserted at `inserted_at_secs` with `ttl` falls due
/// for renewal: at `threshold` of its TTL, or `REFRESH_LEAD_SECS` before it
/// expires, whichever comes first.
///
/// The lead never pulls the renewal before half the TTL. Without that bound
/// a TTL just above the lead would be renewed every second or so, since each
/// renewal brings the same TTL back; the scan this replaced was capped at
/// one pass a minute, so it never showed. Never earlier than the second after
/// insertion either.
pub fn refresh_due_at(inserted_at_secs: u64, ttl: u32, threshold: f64) -> u64 {
    let ttl = u64::from(ttl);
    let proportional = (ttl as f64 * threshold.clamp(0.0, 1.0)) as u64;
    let lead = if ttl > REFRESH_LEAD_SECS {
        (ttl - REFRESH_LEAD_SECS).max(ttl.div_ceil(2))
    } else {
        ttl
    };
    inserted_at_secs + proportional.min(lead).max(1)
}

/// Where the cache leaves refresh timers for the worker, which collects them
/// once a second.
///
/// Arming a timer is on the insert path, so it is kept to an uncontended
/// lock and a push: each thread has its own shard, and nothing is woken,
/// since no timer falls due before the worker's next tick anyway. Bounded per
/// shard: a thread that armed `capacity` timers since the last collection
/// gets the next one back, and the caller counts it as shed. The bound is per
/// thread rather than split between threads, so a burst that lands on one
/// thread gets all of it.
#[derive(Debug)]
pub struct TimerInbox {
    shards: Box<[Mutex<Vec<ScheduledRefresh>>]>,
    shard_capacity: usize,
}

impl TimerInbox {
    pub fn new(capacity_per_thread: usize) -> Self {
        Self {
            shards: (0..INBOX_SHARDS).map(|_| Mutex::default()).collect(),
            shard_capacity: capacity_per_thread.max(1),
        }
    }

    /// Leaves `timer` for the worker, or hands it back when this thread's
    /// shard is full.
    pub fn push(&self, timer: ScheduledRefresh) -> Result<(), ScheduledRefresh> {
        let shard = INBOX_SHARD.with(|shard| *shard);
        let mut timers = self.shards[shard]
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if timers.len() >= self.shard_capacity {
            return Err(timer);
        }
        timers.push(timer);
        Ok(())
    }

    /// Hands every timer left since the last call to `each`. Each shard is
    /// swapped out under its lock and processed after, so producers wait for
    /// a swap, never for the processing. The replacement is sized like the
    /// batch it replaces, so a steady insert rate pushes without reallocating.
    pub fn drain(&self, mut each: impl FnMut(ScheduledRefresh)) {
        for shard in self.shards.iter() {
            let timers = {
                let mut timers = shard.lock().unwrap_or_else(PoisonError::into_inner);
                let len = timers.len();
                std::mem::replace(&mut *timers, Vec::with_capacity(len))
            };
            timers.into_iter().for_each(&mut each);
        }
    }
}

/// Timers by the second they fall due.
///
/// Retries live apart from first attempts so a first-attempt timer is a bare
/// key: this is one entry per cached record, and a flag would pad every one.
#[derive(Debug, Default)]
pub struct RefreshSchedule {
    timers: BTreeMap<u64, Vec<CacheKey>>,
    retries: BTreeMap<u64, Vec<CacheKey>>,
    len: usize,
}

impl RefreshSchedule {
    pub fn register(&mut self, timer: ScheduledRefresh) {
        let by_second = if timer.retry {
            &mut self.retries
        } else {
            &mut self.timers
        };
        by_second
            .entry(timer.due_at_secs)
            .or_default()
            .push(timer.key);
        self.len += 1;
    }

    /// Removes and returns every timer due at or before `now_secs`, earliest
    /// second first.
    pub fn take_due(&mut self, now_secs: u64) -> Vec<ScheduledRefresh> {
        let mut due = Vec::new();
        for (by_second, retry) in [(&mut self.timers, false), (&mut self.retries, true)] {
            while let Some(entry) = by_second.first_entry() {
                if *entry.key() > now_secs {
                    break;
                }
                let due_at_secs = *entry.key();
                due.extend(entry.remove().into_iter().map(|key| ScheduledRefresh {
                    due_at_secs,
                    key,
                    retry,
                }));
            }
        }
        due.sort_by_key(|timer| timer.due_at_secs);
        self.len -= due.len();
        due
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Drops the timers `keep` rejects, such as those for keys no longer
    /// cached. Linear in the timers held, so it is for the rare sweep.
    pub fn retain(&mut self, mut keep: impl FnMut(&CacheKey) -> bool) {
        let mut kept = 0;
        for by_second in [&mut self.timers, &mut self.retries] {
            by_second.retain(|_, keys| {
                keys.retain(&mut keep);
                kept += keys.len();
                !keys.is_empty()
            });
        }
        self.len = kept;
    }
}
