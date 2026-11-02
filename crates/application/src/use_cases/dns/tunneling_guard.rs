use ferrous_dns_domain::{RecordType, TunnelingAction, TunnelingDetectionConfig};
use std::net::IpAddr;
use std::sync::Arc;

/// Outcome of the hot-path tunneling check (phase 1).
pub(super) enum TunnelingVerdict {
    /// No tunneling signal detected.
    Clean,
    /// A tunneling signal was detected with measurable details.
    Detected {
        signal: &'static str,
        measured: f32,
        threshold: f32,
    },
}

/// Guards DNS queries against tunneling attempts on the hot path.
///
/// Performs O(1) checks only: FQDN length, label length, and NULL record type.
/// Statistical analysis (entropy, query rate) runs in a separate background task.
pub(super) struct TunnelingGuard {
    enabled: bool,
    action: TunnelingAction,
    max_fqdn_length: usize,
    max_label_length: usize,
    block_null_queries: bool,
}

impl TunnelingGuard {
    pub(super) fn from_config(config: &TunnelingDetectionConfig) -> Self {
        Self {
            enabled: config.enabled,
            action: config.action,
            max_fqdn_length: config.max_fqdn_length,
            max_label_length: config.max_label_length,
            block_null_queries: config.block_null_queries,
        }
    }

    pub(super) fn disabled() -> Self {
        Self {
            enabled: false,
            action: TunnelingAction::Block,
            max_fqdn_length: 120,
            max_label_length: 50,
            block_null_queries: true,
        }
    }

    pub(super) fn action(&self) -> TunnelingAction {
        self.action
    }

    /// Performs O(1) tunneling checks on the hot path.
    ///
    /// Zero heap allocations: `domain` is `&str`, labels are slices.
    pub(super) fn check(&self, domain: &str, record_type: RecordType) -> TunnelingVerdict {
        if !self.enabled {
            return TunnelingVerdict::Clean;
        }

        if domain.len() > self.max_fqdn_length {
            return TunnelingVerdict::Detected {
                signal: "fqdn_length",
                measured: domain.len() as f32,
                threshold: self.max_fqdn_length as f32,
            };
        }

        for label in domain.split('.') {
            if label.len() > self.max_label_length {
                return TunnelingVerdict::Detected {
                    signal: "label_length",
                    measured: label.len() as f32,
                    threshold: self.max_label_length as f32,
                };
            }
        }

        if self.block_null_queries && record_type == RecordType::NULL {
            return TunnelingVerdict::Detected {
                signal: "null_record_type",
                measured: 1.0,
                threshold: 0.0,
            };
        }

        TunnelingVerdict::Clean
    }
}

/// Event emitted to the background analysis task after each query.
pub struct TunnelingAnalysisEvent {
    pub domain: Arc<str>,
    pub record_type: RecordType,
    pub client_ip: IpAddr,
    pub was_nxdomain: bool,
}
