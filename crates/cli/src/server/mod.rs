pub mod dns;
pub mod doh;
pub mod web;

pub use dns::dot::start_dot_server;
pub use dns::start_dns_server;
pub use dns::tls_config::load_server_tls_config;
pub use web::start_doh_server;
pub use web::start_web_server;

/// Abstraction for a DNS protocol server that can be started independently.
/// Implement this trait to add new protocols (DoT, DoH, etc.) without
/// modifying existing code.
#[allow(dead_code)]
pub trait DnsProtocolServer: Send + Sync {
    fn name(&self) -> &'static str;
    fn start(&self) -> impl std::future::Future<Output = anyhow::Result<()>> + Send;
}
