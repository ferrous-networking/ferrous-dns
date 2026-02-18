use std::net::IpAddr;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct ClientSubnet {
    pub id: Option<i64>,
    pub subnet_cidr: Arc<str>,
    pub group_id: i64,
    pub comment: Option<Arc<str>>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}

impl ClientSubnet {
    pub fn new(subnet_cidr: String, group_id: i64, comment: Option<String>) -> Self {
        Self {
            id: None,
            subnet_cidr: Arc::from(subnet_cidr.as_str()),
            group_id,
            comment: comment.map(|s| Arc::from(s.as_str())),
            created_at: None,
            updated_at: None,
        }
    }

    pub fn validate_cidr(cidr: &str) -> Result<(), String> {
        if cidr.is_empty() {
            return Err("CIDR cannot be empty".to_string());
        }

        if !cidr.contains('/') {
            return Err("CIDR must include prefix (e.g., 192.168.1.0/24)".to_string());
        }

        Ok(())
    }
}

pub struct SubnetMatcher {
    subnets: Vec<(ipnetwork::IpNetwork, i64)>,
}

impl SubnetMatcher {
    pub fn new(subnets: Vec<ClientSubnet>) -> Result<Self, String> {
        let mut networks = Vec::new();

        for subnet in subnets {
            let network: ipnetwork::IpNetwork = subnet
                .subnet_cidr
                .parse()
                .map_err(|e| format!("Invalid CIDR {}: {}", subnet.subnet_cidr, e))?;
            networks.push((network, subnet.group_id));
        }

        Ok(Self { subnets: networks })
    }

    pub fn find_group_for_ip(&self, ip: IpAddr) -> Option<i64> {
        let mut best_match: Option<(u8, i64)> = None;

        for (network, group_id) in &self.subnets {
            if network.contains(ip) {
                let prefix = network.prefix();

                match best_match {
                    None => best_match = Some((prefix, *group_id)),
                    Some((existing_prefix, _)) if prefix > existing_prefix => {
                        best_match = Some((prefix, *group_id));
                    }
                    _ => {}
                }
            }
        }

        best_match.map(|(_, group_id)| group_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_cidr() {
        assert!(ClientSubnet::validate_cidr("192.168.1.0/24").is_ok());
        assert!(ClientSubnet::validate_cidr("10.0.0.0/8").is_ok());
        assert!(ClientSubnet::validate_cidr("").is_err());
        assert!(ClientSubnet::validate_cidr("192.168.1.0").is_err());
    }

    #[test]
    fn test_subnet_matcher_finds_match() {
        let subnets = vec![
            ClientSubnet::new("192.168.1.0/24".to_string(), 2, None),
            ClientSubnet::new("10.0.0.0/8".to_string(), 3, None),
        ];

        let matcher = SubnetMatcher::new(subnets).unwrap();

        let ip: IpAddr = "192.168.1.50".parse().unwrap();
        assert_eq!(matcher.find_group_for_ip(ip), Some(2));

        let ip2: IpAddr = "10.5.10.20".parse().unwrap();
        assert_eq!(matcher.find_group_for_ip(ip2), Some(3));

        let ip3: IpAddr = "8.8.8.8".parse().unwrap();
        assert_eq!(matcher.find_group_for_ip(ip3), None);
    }

    #[test]
    fn test_subnet_matcher_most_specific() {
        let subnets = vec![
            ClientSubnet::new("10.0.0.0/8".to_string(), 3, None),
            ClientSubnet::new("10.1.0.0/16".to_string(), 4, None),
            ClientSubnet::new("10.1.1.0/24".to_string(), 5, None),
        ];

        let matcher = SubnetMatcher::new(subnets).unwrap();

        let ip: IpAddr = "10.1.1.50".parse().unwrap();
        assert_eq!(matcher.find_group_for_ip(ip), Some(5));
    }
}
