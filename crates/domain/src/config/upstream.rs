use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use super::local_records::LocalDnsRecord;
use crate::errors::domain_error::DomainError;

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct UpstreamPool {
    pub name: String,

    pub strategy: UpstreamStrategy,

    #[serde(default = "default_priority")]
    pub priority: u8,

    pub servers: Vec<String>,

    #[serde(default)]
    pub weight: Option<u32>,

    /// Domains this pool answers, together with every name under them, as
    /// configured (Unicode or punycode). Empty for a default pool, which
    /// answers every name no pool claims.
    #[serde(default)]
    pub domains: Vec<String>,

    /// Client group ids `domains` are routed for. Empty routes them for every client.
    #[serde(default)]
    pub groups: Vec<i64>,

    /// The pool answers an internal, unsigned zone: its answers skip DNSSEC
    /// validation and rebinding protection, like `local_dns_server` answers.
    #[serde(default)]
    pub internal: bool,
}

impl Default for UpstreamPool {
    fn default() -> Self {
        Self {
            name: String::new(),
            strategy: UpstreamStrategy::default(),
            priority: default_priority(),
            servers: Vec::new(),
            weight: None,
            domains: Vec::new(),
            groups: Vec::new(),
            internal: false,
        }
    }
}

impl UpstreamPool {
    /// Whether the pool answers only its `domains`, never the default walk.
    pub fn is_conditional(&self) -> bool {
        !self.domains.is_empty()
    }

    /// `domains` as the resolver matches them: lowercase punycode, without
    /// the dots at either end.
    pub fn normalized_domains(&self) -> Result<Vec<String>, DomainError> {
        self.domains
            .iter()
            .map(|domain| {
                normalize_route_domain(domain).map_err(|reason| {
                    DomainError::ConfigError(format!(
                        "Pool '{}': domain '{domain}': {reason}",
                        self.name
                    ))
                })
            })
            .collect()
    }
}

/// Normalizes a domain a pool routes: trims it, drops one leading and one
/// trailing dot, and converts it to lowercase punycode (`рф` → `xn--p1ai`),
/// the form query names arrive in.
pub fn normalize_route_domain(domain: &str) -> Result<String, String> {
    let trimmed = domain.trim();
    let trimmed = trimmed.strip_prefix('.').unwrap_or(trimmed);
    let trimmed = trimmed.strip_suffix('.').unwrap_or(trimmed);
    if trimmed.contains('*') {
        return Err("a wildcard is not needed: a domain already covers every name under it".into());
    }
    let ascii = if trimmed.is_ascii() {
        trimmed.to_ascii_lowercase()
    } else {
        idna::domain_to_ascii(trimmed).map_err(|e| format!("not a valid domain name ({e})"))?
    };
    LocalDnsRecord::validate_domain(&ascii)?;
    Ok(ascii)
}

/// Checks the routing the pools describe as a whole: every domain parses,
/// `groups` and `internal` only qualify a pool that has `domains`, some pool
/// still answers every other name, and no domain is claimed twice for the
/// same clients.
pub fn validate_pool_routes(pools: &[UpstreamPool]) -> Result<(), DomainError> {
    if pools.is_empty() {
        return Ok(());
    }
    if pools.iter().all(UpstreamPool::is_conditional) {
        return Err(DomainError::ConfigError(
            "At least one pool must have no domains, to answer every other query".into(),
        ));
    }

    let mut claimed: HashMap<(String, Option<i64>), &str> = HashMap::new();
    for pool in pools {
        if !pool.is_conditional() {
            if !pool.groups.is_empty() {
                return Err(DomainError::ConfigError(format!(
                    "Pool '{}' sets groups without domains: groups only choose who a pool's domains are routed for",
                    pool.name
                )));
            }
            if pool.internal {
                return Err(DomainError::ConfigError(format!(
                    "Pool '{}' is internal without domains: only a pool that answers its own domains can be internal",
                    pool.name
                )));
            }
            continue;
        }

        if let Some(id) = pool
            .groups
            .iter()
            .find(|id| u32::try_from(**id).map_or(true, |id| id == 0))
        {
            return Err(DomainError::ConfigError(format!(
                "Pool '{}': {id} is not a client group id",
                pool.name
            )));
        }

        let scopes: Vec<Option<i64>> = if pool.groups.is_empty() {
            vec![None]
        } else {
            pool.groups.iter().copied().map(Some).collect()
        };
        for domain in pool.normalized_domains()? {
            for scope in &scopes {
                let owner = claimed
                    .entry((domain.clone(), *scope))
                    .or_insert(pool.name.as_str());
                if *owner != pool.name.as_str() {
                    let clients = match scope {
                        Some(id) => format!("client group {id}"),
                        None => "every client".to_string(),
                    };
                    return Err(DomainError::ConfigError(format!(
                        "Domain '{domain}' is routed to both pool '{owner}' and pool '{}' for {clients}",
                        pool.name
                    )));
                }
            }
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, Default)]
pub enum UpstreamStrategy {
    #[default]
    Parallel,

    Failover,

    Balanced,
}

impl UpstreamStrategy {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Parallel => "parallel",
            Self::Failover => "failover",
            Self::Balanced => "balanced",
        }
    }
}

impl std::fmt::Display for UpstreamStrategy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Parallel => f.write_str("Parallel"),
            Self::Failover => f.write_str("Failover"),
            Self::Balanced => f.write_str("Balanced"),
        }
    }
}

fn default_priority() -> u8 {
    1
}
