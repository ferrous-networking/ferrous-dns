//! An upstream whose hostname never resolved fails every query. That error is
//! what Settings > System Status shows for it, so it must say what went wrong
//! and how to fix it.

use ferrous_dns_domain::{DnsProtocol, DomainError};
use ferrous_dns_infrastructure::dns::transport::get_or_create_transport;
use std::time::Duration;

#[tokio::test]
async fn an_upstream_without_an_address_says_how_to_fix_it() {
    let query = [0u8; 12];
    for (server, label) in [
        ("udp://upstream.test:53", "UDP"),
        ("tcp://upstream.test:53", "TCP"),
        ("tls://upstream.test:853", "TLS"),
        ("doq://upstream.test:853", "QUIC"),
    ] {
        let protocol: DnsProtocol = server.parse().unwrap();
        let err = get_or_create_transport(&protocol)
            .unwrap()
            .send(&query, Duration::from_secs(1))
            .await
            .unwrap_err();

        let DomainError::IoError(message) = &err else {
            panic!("{server}: must stay a transport error so pools fail over, got {err:?}");
        };
        let addr = server.split_once("://").unwrap().1;
        assert_eq!(
            message,
            &format!(
                "{label} upstream {addr} has no IP address yet: looking up its hostname failed. \
                 It is retried automatically; if this machine uses Ferrous DNS as its own \
                 resolver, set Local DNS server (Settings > DNS Settings) to your router"
            ),
            "{server}"
        );
    }
}
