use ferrous_dns_infrastructure::dns::proxy_protocol::{
    read_proxy_v2_client_ip, ProxyProtocolError,
};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const PROXY_V2_SIGNATURE: [u8; 12] = *b"\r\n\r\n\0\r\nQUIT\n";

fn build_tcp4_header(src_ip: [u8; 4], dst_ip: [u8; 4], src_port: u16, dst_port: u16) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&PROXY_V2_SIGNATURE);
    buf.push(0x21); // version 2, PROXY command
    buf.push(0x11); // TCPv4
    buf.extend_from_slice(&12u16.to_be_bytes()); // additional len: 4+4+2+2
    buf.extend_from_slice(&src_ip);
    buf.extend_from_slice(&dst_ip);
    buf.extend_from_slice(&src_port.to_be_bytes());
    buf.extend_from_slice(&dst_port.to_be_bytes());
    buf
}

fn build_tcp6_header(src_ip: [u8; 16], dst_ip: [u8; 16], src_port: u16, dst_port: u16) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&PROXY_V2_SIGNATURE);
    buf.push(0x21); // version 2, PROXY command
    buf.push(0x21); // TCPv6
    buf.extend_from_slice(&36u16.to_be_bytes()); // additional len: 16+16+2+2
    buf.extend_from_slice(&src_ip);
    buf.extend_from_slice(&dst_ip);
    buf.extend_from_slice(&src_port.to_be_bytes());
    buf.extend_from_slice(&dst_port.to_be_bytes());
    buf
}

fn build_local_header() -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&PROXY_V2_SIGNATURE);
    buf.push(0x20); // version 2, LOCAL command
    buf.push(0x00); // UNSPEC
    buf.extend_from_slice(&0u16.to_be_bytes()); // no additional bytes
    buf
}

#[tokio::test]
async fn test_proxy_v2_tcp4_returns_real_client_ip() {
    let src_ip = [10, 0, 0, 100];
    let dst_ip = [192, 168, 1, 1];
    let header = build_tcp4_header(src_ip, dst_ip, 54321, 53);

    let peer_addr: IpAddr = "127.0.0.1".parse().unwrap();
    let mut stream = header.as_slice();
    let result = read_proxy_v2_client_ip(&mut stream, peer_addr).await;

    assert!(result.is_ok());
    assert_eq!(result.unwrap(), IpAddr::V4(Ipv4Addr::new(10, 0, 0, 100)));
}

#[tokio::test]
async fn test_proxy_v2_tcp6_returns_real_client_ip() {
    let src_ip = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let dst_ip = [0; 16];
    let header = build_tcp6_header(src_ip, dst_ip, 54321, 853);

    let peer_addr: IpAddr = "::1".parse().unwrap();
    let mut stream = header.as_slice();
    let result = read_proxy_v2_client_ip(&mut stream, peer_addr).await;

    assert!(result.is_ok());
    let expected = IpAddr::V6(Ipv6Addr::from(src_ip));
    assert_eq!(result.unwrap(), expected);
}

#[tokio::test]
async fn test_proxy_v2_local_command_returns_peer_addr() {
    let header = build_local_header();

    let peer_addr: IpAddr = "172.16.0.5".parse().unwrap();
    let mut stream = header.as_slice();
    let result = read_proxy_v2_client_ip(&mut stream, peer_addr).await;

    assert!(result.is_ok());
    assert_eq!(result.unwrap(), peer_addr);
}

#[tokio::test]
async fn test_proxy_v2_invalid_signature_returns_error() {
    let mut header = vec![0u8; 16];
    header[0] = 0xFF; // corrupt signature

    let peer_addr: IpAddr = "127.0.0.1".parse().unwrap();
    let mut stream = header.as_slice();
    let result = read_proxy_v2_client_ip(&mut stream, peer_addr).await;

    assert!(matches!(result, Err(ProxyProtocolError::InvalidSignature)));
}

#[tokio::test]
async fn test_proxy_v2_invalid_version_returns_error() {
    let mut header = build_tcp4_header([1, 2, 3, 4], [5, 6, 7, 8], 1234, 53);
    header[12] = 0x11; // version nibble = 1, not 2

    let peer_addr: IpAddr = "127.0.0.1".parse().unwrap();
    let mut stream = header.as_slice();
    let result = read_proxy_v2_client_ip(&mut stream, peer_addr).await;

    assert!(matches!(result, Err(ProxyProtocolError::InvalidVersion)));
}

#[tokio::test]
async fn test_proxy_v2_tlv_extensions_are_skipped() {
    let src_ip = [192, 168, 100, 1];
    let dst_ip = [10, 10, 0, 1];
    let mut header = Vec::new();
    header.extend_from_slice(&PROXY_V2_SIGNATURE);
    header.push(0x21); // version 2, PROXY command
    header.push(0x11); // TCPv4
    let additional_len: u16 = 12 + 6; // addresses + 6 bytes of TLV
    header.extend_from_slice(&additional_len.to_be_bytes());
    header.extend_from_slice(&src_ip);
    header.extend_from_slice(&dst_ip);
    header.extend_from_slice(&54321u16.to_be_bytes());
    header.extend_from_slice(&53u16.to_be_bytes());
    header.extend_from_slice(&[0x01, 0x04, 0x00, 0x00, 0x00, 0x00]); // fake TLV

    let peer_addr: IpAddr = "127.0.0.1".parse().unwrap();
    let mut stream = header.as_slice();
    let result = read_proxy_v2_client_ip(&mut stream, peer_addr).await;

    assert!(result.is_ok());
    assert_eq!(result.unwrap(), IpAddr::V4(Ipv4Addr::new(192, 168, 100, 1)));
}

#[tokio::test]
async fn test_proxy_v2_empty_stream_returns_io_error() {
    let peer_addr: IpAddr = "127.0.0.1".parse().unwrap();
    let mut stream: &[u8] = &[];
    let result = read_proxy_v2_client_ip(&mut stream, peer_addr).await;

    assert!(matches!(result, Err(ProxyProtocolError::Io(_))));
}

#[tokio::test]
async fn test_proxy_v2_truncated_header_returns_io_error() {
    // Only 8 bytes — incomplete 16-byte fixed header
    let partial = &PROXY_V2_SIGNATURE[..8];
    let peer_addr: IpAddr = "127.0.0.1".parse().unwrap();
    let mut stream = partial;
    let result = read_proxy_v2_client_ip(&mut stream, peer_addr).await;

    assert!(matches!(result, Err(ProxyProtocolError::Io(_))));
}

#[tokio::test]
async fn test_proxy_v2_unknown_command_returns_error() {
    let mut header = build_tcp4_header([1, 2, 3, 4], [5, 6, 7, 8], 1234, 53);
    header[12] = 0x2F; // version 2, command nibble = 0x0F (unknown)

    let peer_addr: IpAddr = "127.0.0.1".parse().unwrap();
    let mut stream = header.as_slice();
    let result = read_proxy_v2_client_ip(&mut stream, peer_addr).await;

    assert!(matches!(result, Err(ProxyProtocolError::UnknownCommand)));
}

#[tokio::test]
async fn test_proxy_v2_additional_len_too_large_returns_error() {
    let mut header = Vec::new();
    header.extend_from_slice(&PROXY_V2_SIGNATURE);
    header.push(0x21); // version 2, PROXY command
    header.push(0x11); // TCPv4
    header.extend_from_slice(&60000u16.to_be_bytes()); // way over MAX_ADDITIONAL_LEN

    let peer_addr: IpAddr = "127.0.0.1".parse().unwrap();
    let mut stream = header.as_slice();
    let result = read_proxy_v2_client_ip(&mut stream, peer_addr).await;

    assert!(matches!(
        result,
        Err(ProxyProtocolError::AdditionalLenTooLarge)
    ));
}

#[tokio::test]
async fn test_proxy_v2_tcp4_truncated_address_block_returns_io_error() {
    let mut header = Vec::new();
    header.extend_from_slice(&PROXY_V2_SIGNATURE);
    header.push(0x21); // version 2, PROXY command
    header.push(0x11); // TCPv4
    header.extend_from_slice(&12u16.to_be_bytes()); // claims 12 bytes
    header.extend_from_slice(&[1, 2, 3]); // only 3 bytes — truncated

    let peer_addr: IpAddr = "127.0.0.1".parse().unwrap();
    let mut stream = header.as_slice();
    let result = read_proxy_v2_client_ip(&mut stream, peer_addr).await;

    assert!(matches!(result, Err(ProxyProtocolError::Io(_))));
}

#[tokio::test]
async fn test_proxy_v2_unspec_family_returns_peer_addr() {
    let mut header = Vec::new();
    header.extend_from_slice(&PROXY_V2_SIGNATURE);
    header.push(0x21); // version 2, PROXY command
    header.push(0x00); // UNSPEC family
    header.extend_from_slice(&0u16.to_be_bytes()); // no additional bytes

    let peer_addr: IpAddr = "10.0.0.5".parse().unwrap();
    let mut stream = header.as_slice();
    let result = read_proxy_v2_client_ip(&mut stream, peer_addr).await;

    assert!(result.is_ok());
    assert_eq!(result.unwrap(), peer_addr);
}
