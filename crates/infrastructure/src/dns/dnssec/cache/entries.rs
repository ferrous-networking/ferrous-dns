use super::super::types::{DnskeyRecord, DsRecord};
use super::super::validation::ValidationResult;
use std::time::Instant;

#[derive(Debug, Clone)]
pub struct ValidationEntry {
    pub(super) result: ValidationResult,
    pub(super) expires_at: Instant,
}

impl ValidationEntry {
    pub fn new(result: ValidationResult, ttl_secs: u32) -> Self {
        Self {
            result,
            expires_at: Instant::now() + std::time::Duration::from_secs(ttl_secs as u64),
        }
    }

    pub fn is_expired(&self) -> bool {
        Instant::now() >= self.expires_at
    }

    pub fn result(&self) -> &ValidationResult {
        &self.result
    }
}

#[derive(Debug, Clone)]
pub struct DnskeyEntry {
    pub(super) keys: Vec<DnskeyRecord>,
    pub(super) expires_at: Instant,
}

impl DnskeyEntry {
    pub fn new(keys: Vec<DnskeyRecord>, ttl_secs: u32) -> Self {
        Self {
            keys,
            expires_at: Instant::now() + std::time::Duration::from_secs(ttl_secs as u64),
        }
    }

    pub fn is_expired(&self) -> bool {
        Instant::now() >= self.expires_at
    }

    pub fn keys(&self) -> &[DnskeyRecord] {
        &self.keys
    }
}

#[derive(Debug, Clone)]
pub struct DsEntry {
    pub(super) records: Vec<DsRecord>,
    pub(super) expires_at: Instant,
}

impl DsEntry {
    pub fn new(records: Vec<DsRecord>, ttl_secs: u32) -> Self {
        Self {
            records,
            expires_at: Instant::now() + std::time::Duration::from_secs(ttl_secs as u64),
        }
    }

    pub fn is_expired(&self) -> bool {
        Instant::now() >= self.expires_at
    }

    pub fn records(&self) -> &[DsRecord] {
        &self.records
    }
}
