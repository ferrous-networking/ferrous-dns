use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LocalDnsRecord {
    pub hostname: String,

    #[serde(default)]
    pub domain: Option<String>,

    pub ip: String,

    pub record_type: String,

    #[serde(default)]
    pub ttl: Option<u32>,
}

impl LocalDnsRecord {
    pub fn fqdn(&self, default_domain: &Option<String>) -> String {
        if let Some(ref domain) = self.domain {
            format!("{}.{}", self.hostname, domain)
        } else if let Some(ref default) = default_domain {
            format!("{}.{}", self.hostname, default)
        } else {
            self.hostname.clone()
        }
    }

    pub fn ttl_or_default(&self) -> u32 {
        self.ttl.unwrap_or(300)
    }
}
