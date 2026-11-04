//! Client responses counted by RCODE where they leave the DNS handler.

use std::sync::atomic::{AtomicU64, Ordering};

/// The RCODEs `/metrics` names, indexed by their value (RFC 1035 §4.1.1); any
/// other value counts as `OTHER`. BADCOOKIE (23) is an extended RCODE whose
/// header bits read 7, so it lands in `OTHER` too.
pub const RCODE_LABELS: [&str; 7] = [
    "NOERROR", "FORMERR", "SERVFAIL", "NXDOMAIN", "NOTIMP", "REFUSED", "OTHER",
];

const NOERROR: usize = 0;
const OTHER: usize = RCODE_LABELS.len() - 1;

/// One counter per cache line: every worker bumps `NOERROR` on every cache hit.
#[derive(Debug, Default)]
#[repr(align(64))]
struct Slot(AtomicU64);

/// Monotonic since boot, shared by every transport's handler; `/metrics` reads it.
#[derive(Debug, Default)]
pub struct ResponseCounters {
    slots: [Slot; RCODE_LABELS.len()],
}

impl ResponseCounters {
    /// Counts `reply` by the RCODE in its header.
    #[inline]
    pub fn record(&self, reply: &[u8]) {
        let rcode = reply
            .get(3)
            .map_or(OTHER, |flags| usize::from(flags & 0x0F));
        self.slots[rcode.min(OTHER)]
            .0
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Counts a reply known to be NOERROR without reading it.
    #[inline]
    pub fn record_noerror(&self) {
        self.slots[NOERROR].0.fetch_add(1, Ordering::Relaxed);
    }

    pub fn totals(&self) -> ResponseTotals {
        ResponseTotals {
            by_rcode: std::array::from_fn(|i| self.slots[i].0.load(Ordering::Relaxed)),
        }
    }
}

/// [`ResponseCounters`] read at one instant, in [`RCODE_LABELS`] order.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ResponseTotals {
    pub by_rcode: [u64; RCODE_LABELS.len()],
}
