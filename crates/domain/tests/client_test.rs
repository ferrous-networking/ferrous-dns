use ferrous_dns_domain::client::Client;
use std::net::IpAddr;
use std::sync::Arc;

#[test]
fn test_client_new() {
    let ip: IpAddr = "192.168.1.100".parse().unwrap();
    let client = Client::new(ip);

    assert_eq!(client.ip_address, ip);
    assert!(client.id.is_none());
    assert!(client.mac_address.is_none());
    assert!(client.hostname.is_none());
    assert_eq!(client.query_count, 0);
}

#[test]
fn test_should_update_mac_when_none() {
    let ip: IpAddr = "192.168.1.100".parse().unwrap();
    let client = Client::new(ip);

    assert!(client.should_update_mac());
}

#[test]
fn test_should_update_hostname_when_none() {
    let ip: IpAddr = "192.168.1.100".parse().unwrap();
    let client = Client::new(ip);

    assert!(client.should_update_hostname());
}

#[test]
fn test_should_not_update_mac_when_recent() {
    let ip: IpAddr = "192.168.1.100".parse().unwrap();
    let mut client = Client::new(ip);
    client.mac_address = Some(Arc::from("aa:bb:cc:dd:ee:ff"));
    client.last_mac_update = Some(chrono::Utc::now().timestamp());

    assert!(!client.should_update_mac());
}
