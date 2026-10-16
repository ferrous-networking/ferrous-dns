//! Per-entry timers: renewals and expiries.
//!
//! The cache arms a timer when it stores or renews an entry, for the second
//! that entry falls due, and the refresh worker takes timers as their second
//! comes. Nothing scans the cache to find what is due, so the cost follows the
//! work, and an entry is renewed on time whatever its TTL is relative to any
//! maintenance interval.
//!
//! Removal works the same way. An entry nobody renews gets a timer for the
//! second it stops being usable, and a timer that finds its entry dead removes
//! it. Every entry the cache can lose has at least one timer pending at all
//! times, so no pass over the cache has to look for dead entries either.
//!
//! A timer holds only the key and its second; what it does when it fires is
//! read from the record. A dead entry is removed by whichever timer finds it.
//! A live one is renewed only by the timer whose second the record holds as
//! its pending renewal: any other is stale, and spends nothing. So a timer
//! left over by a renewal or a re-arm is harmless.

use super::key::CacheKey;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, PoisonError};

/// How long before expiry an entry is renewed at the latest, unless that
/// would come before half its TTL (see [`refresh_due_at`]).
pub const REFRESH_LEAD_SECS: u64 = 60;

/// Shards of the [`TimerInbox`]. Threads are spread over them round-robin, so
/// past this many threads they share one.
const INBOX_SHARDS: usize = 16;

static NEXT_INBOX_SHARD: AtomicUsize = AtomicUsize::new(0);

thread_local! {
    /// This thread's inbox shard, handed out round-robin on first use.
    static INBOX_SHARD: usize = NEXT_INBOX_SHARD.fetch_add(1, Ordering::Relaxed) % INBOX_SHARDS;
}

/// What a timer is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimerKind {
    /// A positive entry's timer. It removes the entry if dead, renews it if
    /// this is its pending renewal, and is stale otherwise.
    Due,
    /// The one more attempt a renewal on a timer gets when it did not renew
    /// the entry. It gets no further one.
    Retry,
    /// A negative entry's expiry.
    NegativeExpiry,
}

/// A timer on its way to the worker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScheduledRefresh {
    pub due_at_secs: u64,
    pub key: CacheKey,
    pub kind: TimerKind,
}

/// The second an entry inserted at `inserted_at_secs` with `ttl` falls due
/// for renewal: at `threshold` of its TTL, or `REFRESH_LEAD_SECS` before it
/// expires, whichever comes first.
///
/// The lead never pulls the renewal before half the TTL: otherwise a TTL just
/// above the lead would be renewed every second or so, since each renewal
/// brings the same TTL back. A threshold below 0.5 still applies as set.
/// Never earlier than the second after insertion either.
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
/// Arming a timer is on the insert path, so it is kept to a lock that is
/// rarely contended and a push: each thread pushes to the shard it was given,
/// and nothing is woken, since no timer falls due before the worker's next
/// tick anyway. A shard never turns a timer away: an entry whose timer was
/// lost would never be renewed nor removed. A burst costs a timer per insert
/// until the next collection, a fraction of what the entries it stores cost.
#[derive(Debug)]
pub struct TimerInbox {
    shards: Box<[Mutex<Vec<ScheduledRefresh>>]>,
}

impl TimerInbox {
    pub fn new() -> Self {
        Self {
            shards: (0..INBOX_SHARDS).map(|_| Mutex::default()).collect(),
        }
    }

    /// Leaves `timer` for the worker.
    pub fn push(&self, timer: ScheduledRefresh) {
        let shard = INBOX_SHARD.with(|shard| *shard);
        self.shards[shard]
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(timer);
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

impl Default for TimerInbox {
    fn default() -> Self {
        Self::new()
    }
}

/// Timers by the second they fall due.
///
/// Each kind lives apart so a timer is a bare key: this is one entry per
/// cached record, and a tag would pad every one.
#[derive(Debug, Default)]
pub struct RefreshSchedule {
    timers: BTreeMap<u64, Vec<CacheKey>>,
    retries: BTreeMap<u64, Vec<CacheKey>>,
    negatives: BTreeMap<u64, Vec<CacheKey>>,
    len: usize,
}

impl RefreshSchedule {
    pub fn register(&mut self, timer: ScheduledRefresh) {
        let by_second = match timer.kind {
            TimerKind::Due => &mut self.timers,
            TimerKind::Retry => &mut self.retries,
            TimerKind::NegativeExpiry => &mut self.negatives,
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
        for (by_second, kind) in [
            (&mut self.timers, TimerKind::Due),
            (&mut self.retries, TimerKind::Retry),
            (&mut self.negatives, TimerKind::NegativeExpiry),
        ] {
            while let Some(entry) = by_second.first_entry() {
                if *entry.key() > now_secs {
                    break;
                }
                let due_at_secs = *entry.key();
                due.extend(entry.remove().into_iter().map(|key| ScheduledRefresh {
                    due_at_secs,
                    key,
                    kind,
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

    /// One step of a sweep that drops the timers `keep` rejects, such as
    /// those whose entry was evicted. It visits the positive entries' timers
    /// from `from` on, then the negative expiries, until it has looked at
    /// `budget` timers, and returns where to resume, or `None` once it has
    /// been through them all. The first step also sweeps the retries, of
    /// which there are few.
    pub fn sweep(
        &mut self,
        from: SweepFrom,
        budget: usize,
        mut keep: impl FnMut(&CacheKey, TimerKind) -> bool,
    ) -> Option<SweepFrom> {
        let mut removed = 0;
        if from == SweepFrom::START {
            self.retries.retain(|_, keys| {
                let before = keys.len();
                keys.retain(|key| keep(key, TimerKind::Retry));
                removed += before - keys.len();
                !keys.is_empty()
            });
        }
        let mut budget = budget;
        let mut resume = None;
        if from.kind == TimerKind::Due {
            resume = sweep_lane(
                &mut self.timers,
                from.second,
                &mut budget,
                &mut removed,
                |key| keep(key, TimerKind::Due),
            )
            .map(|second| SweepFrom {
                kind: TimerKind::Due,
                second,
            });
        }
        if resume.is_none() {
            let start = if from.kind == TimerKind::NegativeExpiry {
                from.second
            } else {
                0
            };
            resume = sweep_lane(
                &mut self.negatives,
                start,
                &mut budget,
                &mut removed,
                |key| keep(key, TimerKind::NegativeExpiry),
            )
            .map(|second| SweepFrom {
                kind: TimerKind::NegativeExpiry,
                second,
            });
        }
        self.len -= removed;
        resume
    }
}

/// Where a sweep resumes: in the lane of `kind`, `Due` or `NegativeExpiry`,
/// at `second`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SweepFrom {
    pub kind: TimerKind,
    pub second: u64,
}

impl SweepFrom {
    /// The first step of a sweep.
    pub const START: Self = Self {
        kind: TimerKind::Due,
        second: 0,
    };
}

/// Sweeps `lane` from `from` on until `budget` timers have been looked at,
/// adding what it dropped to `removed`. Returns the second to resume from,
/// or `None` once it reached the end.
fn sweep_lane(
    lane: &mut BTreeMap<u64, Vec<CacheKey>>,
    from: u64,
    budget: &mut usize,
    removed: &mut usize,
    mut keep: impl FnMut(&CacheKey) -> bool,
) -> Option<u64> {
    let mut emptied = Vec::new();
    let mut resume = None;
    for (&second, keys) in lane.range_mut(from..) {
        if *budget == 0 {
            resume = Some(second);
            break;
        }
        *budget = budget.saturating_sub(keys.len());
        let before = keys.len();
        keys.retain(&mut keep);
        *removed += before - keys.len();
        if keys.is_empty() {
            emptied.push(second);
        }
    }
    for second in emptied {
        lane.remove(&second);
    }
    resume
}
