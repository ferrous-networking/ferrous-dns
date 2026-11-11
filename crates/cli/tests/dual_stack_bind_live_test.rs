//! `[server] bind_address = "auto"`, the default, against the real binary:
//! DNS and the web server answer IPv4 and IPv6 clients, while a config that
//! names `0.0.0.0` keeps listening on IPv4 only.
#![cfg(target_os = "linux")]

mod common;
mod server_process;

use common::skip_without_dual_stack;
use server_process::{
    accepts_within, http_status, is_refused, server_log, udp_answers, TestConfig, FALLBACK_LINE,
};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

const V4: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
const V6: IpAddr = IpAddr::V6(Ipv6Addr::LOCALHOST);

fn assert_serves(config: &TestConfig, ip: IpAddr) {
    let dns = SocketAddr::new(ip, config.dns_port);
    assert!(
        accepts_within(dns, Duration::from_secs(10)),
        "DNS over TCP on {dns}"
    );
    assert!(udp_answers(dns), "DNS over UDP on {dns}");
    assert_eq!(
        http_status(
            SocketAddr::new(ip, config.web_port),
            "/ferrous/api/v1/health"
        ),
        200,
        "web on {ip}"
    );
}

#[test]
fn test_auto_serves_dns_and_web_on_ipv4_and_ipv6() {
    if skip_without_dual_stack("test_auto_serves_dns_and_web_on_ipv4_and_ipv6") {
        return;
    }
    let config = TestConfig::with_bind_address(Some("auto"), "", "enabled = false");
    let _server = config.start();

    assert_serves(&config, V4);
    assert_serves(&config, V6);
    // The IPv4 fallback is only for kernels without IPv6.
    let log = server_log(config.dir.path());
    assert!(!log.contains(FALLBACK_LINE), "{log}");
}

#[test]
fn test_missing_bind_address_serves_both_families() {
    if skip_without_dual_stack("test_missing_bind_address_serves_both_families") {
        return;
    }
    let config = TestConfig::with_bind_address(None, "", "enabled = false");
    let _server = config.start();

    assert_serves(&config, V4);
    assert_serves(&config, V6);
}

#[test]
fn test_ipv4_bind_address_still_refuses_ipv6() {
    if skip_without_dual_stack("test_ipv4_bind_address_still_refuses_ipv6") {
        return;
    }
    let config = TestConfig::with_bind_address(Some("0.0.0.0"), "", "enabled = false");
    let _server = config.start();

    assert_serves(&config, V4);
    assert!(
        is_refused(SocketAddr::new(V6, config.dns_port)),
        "DNS over TCP on ::1"
    );
    assert!(
        is_refused(SocketAddr::new(V6, config.web_port)),
        "web on ::1"
    );
}
