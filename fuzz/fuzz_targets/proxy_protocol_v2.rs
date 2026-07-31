//! PROXY protocol v2 header parser. Runs before anything else on a TCP/DoT
//! connection when the server sits behind a load balancer, and decides which
//! client IP the rest of the pipeline (rate limiting, per-client rules,
//! query log) will attribute the query to.
//!
//! `tokio::io::AsyncRead` is implemented for `&[u8]`, so the public async
//! entry point can be driven from a plain buffer with no runtime.
#![no_main]

use ferrous_dns_infrastructure::dns::proxy_protocol::read_proxy_v2_client_ip;
use libfuzzer_sys::fuzz_target;
use std::net::{IpAddr, Ipv4Addr};

fuzz_target!(|data: &[u8]| {
    let peer = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));
    let mut reader = data;
    let _ = futures::executor::block_on(read_proxy_v2_client_ip(&mut reader, peer));
});
