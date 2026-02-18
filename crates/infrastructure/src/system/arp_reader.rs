use async_trait::async_trait;
use ferrous_dns_application::ports::{ArpReader, ArpTable};
use ferrous_dns_domain::DomainError;
use std::net::IpAddr;
use std::str::FromStr;
use tokio::fs;
use tracing::{debug, warn};

fn is_valid_mac(mac: &str) -> bool {
    if mac.len() != 17 {
        return false;
    }

    let separator = if mac.contains(':') {
        ':'
    } else if mac.contains('-') {
        '-'
    } else {
        return false;
    };

    let parts: Vec<&str> = mac.split(separator).collect();
    if parts.len() != 6 {
        return false;
    }

    parts
        .iter()
        .all(|part| part.len() == 2 && part.chars().all(|c| c.is_ascii_hexdigit()))
}

pub struct LinuxArpReader {
    arp_path: String,
}

impl LinuxArpReader {
    pub fn new() -> Self {
        Self {
            arp_path: "/proc/net/arp".to_string(),
        }
    }

    pub fn with_path(path: String) -> Self {
        Self { arp_path: path }
    }
}

impl Default for LinuxArpReader {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ArpReader for LinuxArpReader {
    async fn read_arp_table(&self) -> Result<ArpTable, DomainError> {
        let content = fs::read_to_string(&self.arp_path)
            .await
            .map_err(|e| DomainError::IoError(format!("Failed to read ARP cache: {}", e)))?;

        let mut arp_table = ArpTable::new();

        for (line_num, line) in content.lines().enumerate() {
            if line_num == 0 {
                continue;
            }

            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 4 {
                continue;
            }

            let ip_str = fields[0];
            let flags = fields[2];
            let mac = fields[3];

            if flags != "0x2" || mac == "00:00:00:00:00:00" {
                continue;
            }

            if !is_valid_mac(mac) {
                warn!(
                    ip = ip_str,
                    mac = mac,
                    "Invalid MAC address format in ARP table"
                );
                continue;
            }

            match IpAddr::from_str(ip_str) {
                Ok(ip) => {
                    arp_table.insert(ip, mac.to_string());
                }
                Err(e) => {
                    warn!(error = %e, ip = ip_str, "Invalid IP in ARP table");
                }
            }
        }

        debug!(entries = arp_table.len(), "ARP table parsed");
        Ok(arp_table)
    }
}
