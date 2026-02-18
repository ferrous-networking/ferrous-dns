use ferrous_dns_application::ports::ArpReader;
use ferrous_dns_infrastructure::system::arp_reader::LinuxArpReader;
use std::io::Write;
use std::net::IpAddr;
use tempfile::NamedTempFile;

#[tokio::test]
async fn test_parse_valid_arp_table() {
    let content = r#"IP address       HW type     Flags       HW address            Mask     Device
192.168.1.1      0x1         0x2         aa:bb:cc:dd:ee:ff     *        eth0
192.168.1.2      0x1         0x2         11:22:33:44:55:66     *        eth0
192.168.1.10     0x1         0x2         aa:11:22:33:44:55     *        wlan0
"#;

    let mut temp_file = NamedTempFile::new().unwrap();
    temp_file.write_all(content.as_bytes()).unwrap();
    temp_file.flush().unwrap();

    let reader = LinuxArpReader::with_path(temp_file.path().to_str().unwrap().to_string());
    let arp_table = reader.read_arp_table().await.unwrap();

    assert_eq!(arp_table.len(), 3);
    assert_eq!(
        arp_table.get(&"192.168.1.1".parse::<IpAddr>().unwrap()),
        Some(&"aa:bb:cc:dd:ee:ff".to_string())
    );
    assert_eq!(
        arp_table.get(&"192.168.1.2".parse::<IpAddr>().unwrap()),
        Some(&"11:22:33:44:55:66".to_string())
    );
    assert_eq!(
        arp_table.get(&"192.168.1.10".parse::<IpAddr>().unwrap()),
        Some(&"aa:11:22:33:44:55".to_string())
    );
}

#[tokio::test]
async fn test_parse_arp_table_filters_incomplete_entries() {
    let content = r#"IP address       HW type     Flags       HW address            Mask     Device
192.168.1.1      0x1         0x2         aa:bb:cc:dd:ee:ff     *        eth0
192.168.1.2      0x1         0x2         11:22:33:44:55:66     *        eth0
192.168.1.3      0x1         0x0         00:00:00:00:00:00     *        eth0
192.168.1.4      0x1         0x1         ff:ff:ff:ff:ff:ff     *        eth0
"#;

    let mut temp_file = NamedTempFile::new().unwrap();
    temp_file.write_all(content.as_bytes()).unwrap();
    temp_file.flush().unwrap();

    let reader = LinuxArpReader::with_path(temp_file.path().to_str().unwrap().to_string());
    let arp_table = reader.read_arp_table().await.unwrap();

    assert_eq!(arp_table.len(), 2);
    assert!(!arp_table.contains_key(&"192.168.1.3".parse::<IpAddr>().unwrap()));
    assert!(!arp_table.contains_key(&"192.168.1.4".parse::<IpAddr>().unwrap()));
}

#[tokio::test]
async fn test_parse_arp_table_filters_invalid_ips() {
    let content = r#"IP address       HW type     Flags       HW address            Mask     Device
192.168.1.1      0x1         0x2         aa:bb:cc:dd:ee:ff     *        eth0
invalid.ip       0x1         0x2         ff:ff:ff:ff:ff:ff     *        eth0
not-an-ip        0x1         0x2         11:22:33:44:55:66     *        eth0
"#;

    let mut temp_file = NamedTempFile::new().unwrap();
    temp_file.write_all(content.as_bytes()).unwrap();
    temp_file.flush().unwrap();

    let reader = LinuxArpReader::with_path(temp_file.path().to_str().unwrap().to_string());
    let arp_table = reader.read_arp_table().await.unwrap();

    assert_eq!(arp_table.len(), 1);
}

#[tokio::test]
async fn test_empty_arp_table() {
    let content =
        "IP address       HW type     Flags       HW address            Mask     Device\n";

    let mut temp_file = NamedTempFile::new().unwrap();
    temp_file.write_all(content.as_bytes()).unwrap();
    temp_file.flush().unwrap();

    let reader = LinuxArpReader::with_path(temp_file.path().to_str().unwrap().to_string());
    let arp_table = reader.read_arp_table().await.unwrap();

    assert_eq!(arp_table.len(), 0);
}

#[tokio::test]
async fn test_nonexistent_arp_file() {
    let reader = LinuxArpReader::with_path("/nonexistent/path/to/arp".to_string());
    let result = reader.read_arp_table().await;

    assert!(result.is_err());
}

#[tokio::test]
async fn test_malformed_arp_lines() {
    let content = r#"IP address       HW type     Flags       HW address            Mask     Device
192.168.1.1      0x1         0x2         aa:bb:cc:dd:ee:ff     *        eth0
incomplete line
another bad
192.168.1.2
192.168.1.3      0x1         0x2         11:22:33:44:55:66     *        eth0
"#;

    let mut temp_file = NamedTempFile::new().unwrap();
    temp_file.write_all(content.as_bytes()).unwrap();
    temp_file.flush().unwrap();

    let reader = LinuxArpReader::with_path(temp_file.path().to_str().unwrap().to_string());
    let arp_table = reader.read_arp_table().await.unwrap();

    assert_eq!(arp_table.len(), 2);
}

#[tokio::test]
async fn test_ipv6_addresses_in_arp_table() {
    let content = r#"IP address       HW type     Flags       HW address            Mask     Device
192.168.1.1      0x1         0x2         aa:bb:cc:dd:ee:ff     *        eth0
fe80::1          0x1         0x2         11:22:33:44:55:66     *        eth0
"#;

    let mut temp_file = NamedTempFile::new().unwrap();
    temp_file.write_all(content.as_bytes()).unwrap();
    temp_file.flush().unwrap();

    let reader = LinuxArpReader::with_path(temp_file.path().to_str().unwrap().to_string());
    let arp_table = reader.read_arp_table().await.unwrap();

    assert_eq!(arp_table.len(), 2);
    assert!(arp_table.contains_key(&"192.168.1.1".parse::<IpAddr>().unwrap()));
    assert!(arp_table.contains_key(&"fe80::1".parse::<IpAddr>().unwrap()));
}
