use serde::Serialize;
use utoipa::ToSchema;

/// Aggregated DNSSEC validation outcomes over client queries in the period.
#[derive(Serialize, Debug, Clone, Default, ToSchema)]
pub struct DnssecStatsResponse {
    /// Total client queries in the period (the coverage denominator).
    pub total: u64,
    /// Queries that received a DNSSEC determination (any non-null status).
    pub validated: u64,
    pub secure: u64,
    pub insecure: u64,
    pub bogus: u64,
    pub indeterminate: u64,
    /// Delegations served as Insecure because the upstream returned no
    /// authenticated NSEC/NSEC3 proving the DS RRset absent. Unlike the fields
    /// above this is a process-lifetime total, not scoped to the period.
    pub ds_denial_fail_opens: u64,
}
