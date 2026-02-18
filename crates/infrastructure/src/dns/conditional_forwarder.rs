use ferrous_dns_domain::{ConditionalForward, DnsQuery, DomainError};
use std::sync::Arc;
use tracing::{debug, warn};

use super::forwarding::DnsForwarder;

pub struct ConditionalForwarder {
    rules: Vec<ConditionalForward>,
    forwarder: Arc<DnsForwarder>,
}

impl ConditionalForwarder {
    pub fn new(rules: Vec<ConditionalForward>) -> Self {
        debug!(rules_count = rules.len(), "Conditional forwarder created");
        Self {
            rules,
            forwarder: Arc::new(DnsForwarder::new()),
        }
    }

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

    pub fn should_forward(&self, query: &DnsQuery) -> Option<(&ConditionalForward, String)> {
        self.find_matching_rule(query)
            .map(|rule| (rule, rule.server.clone()))
    }
}
