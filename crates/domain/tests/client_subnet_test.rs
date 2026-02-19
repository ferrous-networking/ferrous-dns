use ferrous_dns_domain::{ClientSubnet, SubnetMatcher};
use std::net::IpAddr;

#[test]
fn test_client_subnet_creation_valid() {
    let subnet = ClientSubnet::new("192.168.1.0/24".to_string(), 1, None);

    assert_eq!(subnet.group_id, 1);
    assert_eq!(subnet.subnet_cidr.to_string(), "192.168.1.0/24");
    assert!(subnet.comment.is_none());
    assert!(subnet.id.is_none());
    assert!(subnet.created_at.is_none());
}

#[test]
fn test_client_subnet_creation_with_comment() {
    let subnet = ClientSubnet::new(
        "10.0.0.0/8".to_string(),
        2,
        Some("Office network".to_string()),
    );

    assert_eq!(subnet.group_id, 2);
    assert_eq!(
        subnet.comment.as_ref().map(|s| s.as_ref()),
        Some("Office network")
    );
}

#[test]
fn test_client_subnet_validate_cidr_missing_mask() {
    let result = ClientSubnet::validate_cidr("192.168.1.0");

    assert!(result.is_err());
    assert!(result.unwrap_err().contains("must include prefix"));
}

#[test]
fn test_client_subnet_validate_cidr_empty() {
    let result = ClientSubnet::validate_cidr("");

    assert!(result.is_err());
    assert!(result.unwrap_err().contains("cannot be empty"));
}

#[test]
fn test_client_subnet_validate_cidr_valid() {
    let result = ClientSubnet::validate_cidr("192.168.1.0/24");
    assert!(result.is_ok());
}

#[test]
fn test_client_subnet_with_id_and_timestamp() {
    let mut subnet = ClientSubnet::new("172.16.0.0/12".to_string(), 5, None);
    subnet.id = Some(123);
    subnet.created_at = Some("2024-01-01T00:00:00Z".to_string());

    assert_eq!(subnet.id, Some(123));
    assert_eq!(subnet.created_at, Some("2024-01-01T00:00:00Z".to_string()));
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
fn test_subnet_matcher_most_specific_wins() {
    let subnets = vec![
        ClientSubnet::new("10.0.0.0/8".to_string(), 3, None),
        ClientSubnet::new("10.1.0.0/16".to_string(), 4, None),
        ClientSubnet::new("10.1.1.0/24".to_string(), 5, None),
    ];

    let matcher = SubnetMatcher::new(subnets).unwrap();

    let ip: IpAddr = "10.1.1.50".parse().unwrap();
    assert_eq!(matcher.find_group_for_ip(ip), Some(5));
}
