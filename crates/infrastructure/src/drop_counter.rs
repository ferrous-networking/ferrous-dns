//! Accounting for work deliberately shed under overload.

use std::sync::atomic::{AtomicU64, Ordering};

/// Drops to log: those since the previous report, and since construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DropReport {
    pub since_last: u64,
    pub total: u64,
}

/// Counts shed work and admits at most one report per clock second, so a
/// sustained overload stays visible without turning into per-drop log I/O.
#[derive(Debug, Default)]
pub struct DropCounter {
    total: AtomicU64,
    reported_total: AtomicU64,
    // Zero never equals a real timestamp, so the first drop always reports.
    last_report_secs: AtomicU64,
}

impl DropCounter {
    pub const fn new() -> Self {
        Self {
            total: AtomicU64::new(0),
            reported_total: AtomicU64::new(0),
            last_report_secs: AtomicU64::new(0),
        }
    }

    /// Records one drop at `now_secs`; returns a report if none was made this second.
    #[inline]
    pub fn record(&self, now_secs: u64) -> Option<DropReport> {
        let total = self.total.fetch_add(1, Ordering::Relaxed) + 1;
        let last = self.last_report_secs.load(Ordering::Relaxed);
        if last == now_secs
            || self
                .last_report_secs
                .compare_exchange(last, now_secs, Ordering::Relaxed, Ordering::Relaxed)
                .is_err()
        {
            return None;
        }
        // Reporters from consecutive seconds can finish out of order; the larger total wins.
        let previous = self.reported_total.fetch_max(total, Ordering::Relaxed);
        (total > previous).then(|| DropReport {
            since_last: total - previous,
            total,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reports_once_per_second_with_interval_and_cumulative_counts() {
        let counter = DropCounter::new();
        let reports: Vec<_> = [10, 10, 10, 11, 11, 13, 13, 13, 13]
            .into_iter()
            .filter_map(|now| counter.record(now))
            .collect();
        assert_eq!(
            reports,
            [
                DropReport {
                    since_last: 1,
                    total: 1
                },
                DropReport {
                    since_last: 3,
                    total: 4
                },
                DropReport {
                    since_last: 2,
                    total: 6
                },
            ]
        );
    }

    #[test]
    fn a_later_overload_episode_reports_immediately_after_any_backlog() {
        let counter = DropCounter::new();
        for _ in 0..1_000_000 {
            counter.record(10);
        }
        assert_eq!(
            counter.record(500),
            Some(DropReport {
                since_last: 1_000_000,
                total: 1_000_001
            })
        );
    }
}
