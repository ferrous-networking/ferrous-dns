use super::super::types::{DnskeyRecord, DsRecord};
use super::super::validation::ValidationResult;
use std::time::Instant;

/// Cached validation entry with TTL
#[derive(Debug, Clone)]
pub struct ValidationEntry {
    pub(super) result: ValidationResult,
    pub(super) expires_at: Instant,
}

impl ValidationEntry {
    /// Create new validation entry
    pub fn new(result: ValidationResult, ttl_secs: u32) -> Self {
        Self {
            result,
            expires_at: Instant::now() + std::time::Duration::from_secs(ttl_secs as u64),
        }
    }

    /// Check if entry is expired
    pub fn is_expired(&self) -> bool {
        Instant::now() >= self.expires_at
    }

    /// Get validation result
    pub fn result(&self) -> &ValidationResult {
        &self.result
    }
}

/// Cached DNSKEY entry with TTL
#[derive(Debug, Clone)]
pub struct DnskeyEntry {
    pub(super) keys: Vec<DnskeyRecord>,
    pub(super) expires_at: Instant,
}

impl DnskeyEntry {
    /// Create new DNSKEY entry
    pub fn new(keys: Vec<DnskeyRecord>, ttl_secs: u32) -> Self {
        Self {
            keys,
            expires_at: Instant::now() + std::time::Duration::from_secs(ttl_secs as u64),
        }
    }

    /// Check if entry is expired
    pub fn is_expired(&self) -> bool {
        Instant::now() >= self.expires_at
    }

    /// Get DNSKEY records
    pub fn keys(&self) -> &[DnskeyRecord] {
        &self.keys
    }
}

/// Cached DS entry with TTL
#[derive(Debug, Clone)]
pub struct DsEntry {
    pub(super) records: Vec<DsRecord>,
    pub(super) expires_at: Instant,
}

impl DsEntry {
    /// Create new DS entry
    pub fn new(records: Vec<DsRecord>, ttl_secs: u32) -> Self {
        Self {
            records,
            expires_at: Instant::now() + std::time::Duration::from_secs(ttl_secs as u64),
        }
    }

    /// Check if entry is expired
    pub fn is_expired(&self) -> bool {
        Instant::now() >= self.expires_at
    }

    /// Get DS records
    pub fn records(&self) -> &[DsRecord] {
        &self.records
    }
}
