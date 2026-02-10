use ferrous_dns_domain::{ConditionalForward, DnsQuery, DomainError};
use std::sync::Arc;
use tracing::{debug, warn};

use super::forwarding::DnsForwarder;

/// Conditional forwarder routes queries to specific DNS servers based on domain patterns
///
/// This allows routing:
/// - Local domains (*.home.lan) → Router DHCP server
/// - Corporate domains (*.corp.local) → Corporate DNS
/// - Development domains (*.dev.local) → Local development DNS
pub struct ConditionalForwarder {
    rules: Vec<ConditionalForward>,
    forwarder: Arc<DnsForwarder>,
}

impl ConditionalForwarder {
    /// Create a new conditional forwarder with the given rules
    pub fn new(rules: Vec<ConditionalForward>) -> Self {
        debug!(rules_count = rules.len(), "Conditional forwarder created");
        Self {
            rules,
            forwarder: Arc::new(DnsForwarder::new()),
        }
    }

    /// Find a matching rule for a query
    ///
    /// Returns the first rule that matches both:
    /// 1. The query's domain (exact or subdomain match)
    /// 2. The query's record type (if rule has type filter)
    pub fn find_matching_rule(&self, query: &DnsQuery) -> Option<&ConditionalForward> {
        let record_type_str = query.record_type.to_string();

        for rule in &self.rules {
            if rule.matches(&query.domain, &record_type_str) {
                debug!(
                    domain = %query.domain,
                    record_type = %query.record_type,
                    rule_domain = %rule.domain,
                    rule_server = %rule.server,
                    "Found matching conditional forwarding rule"
                );
                return Some(rule);
            }
        }

        None
    }

    /// Query a specific server for a domain
    ///
    /// This bypasses normal upstream pools and queries the specified server directly.
    pub async fn query_specific_server(
        &self,
        query: &DnsQuery,
        server: &str,
        timeout_ms: u64,
    ) -> Result<Vec<std::net::IpAddr>, DomainError> {
        debug!(
            domain = %query.domain,
            record_type = %query.record_type,
            server = %server,
            "Forwarding query to conditional server"
        );

        match self
            .forwarder
            .query(server, &query.domain, &query.record_type, timeout_ms)
            .await
        {
            Ok(response) => {
                debug!(
                    domain = %query.domain,
                    server = %server,
                    addresses = response.addresses.len(),
                    "Conditional forwarding successful"
                );
                Ok(response.addresses)
            }
            Err(e) => {
                warn!(
                    domain = %query.domain,
                    server = %server,
                    error = %e,
                    "Conditional forwarding failed"
                );
                Err(e)
            }
        }
    }

    /// Check if conditional forwarding should be used for this query
    ///
    /// Returns Some((rule, server)) if a rule matches, None otherwise
    pub fn should_forward(&self, query: &DnsQuery) -> Option<(&ConditionalForward, String)> {
        self.find_matching_rule(query)
            .map(|rule| (rule, rule.server.clone()))
    }
}
