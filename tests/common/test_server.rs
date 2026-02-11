use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::oneshot;

pub struct TestServer {
    addr: SocketAddr,
    shutdown_tx: Option<oneshot::Sender<()>>,
}

impl TestServer {
    pub async fn start() -> Result<Self, std::io::Error> {
        Self::start_on_port(0).await // Random port
    }

    pub async fn start_on_port(port: u16) -> Result<Self, std::io::Error> {
        let addr = SocketAddr::from(([127, 0, 0, 1], port));
        
        let (shutdown_tx, _shutdown_rx) = oneshot::channel();

        Ok(Self {
            addr,
            shutdown_tx: Some(shutdown_tx),
        })
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    pub fn port(&self) -> u16 {
        self.addr.port()
    }

    pub fn shutdown(mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
    }
}

pub struct TestServerBuilder {
    port: Option<u16>,
    cache_enabled: bool,
    dnssec_enabled: bool,
    blocklist_enabled: bool,
}

impl TestServerBuilder {
    pub fn new() -> Self {
        Self {
            port: None,
            cache_enabled: true,
            dnssec_enabled: true,
            blocklist_enabled: true,
        }
    }

    pub fn with_port(mut self, port: u16) -> Self {
        self.port = Some(port);
        self
    }

    pub fn with_cache(mut self, enabled: bool) -> Self {
        self.cache_enabled = enabled;
        self
    }

    pub fn with_dnssec(mut self, enabled: bool) -> Self {
        self.dnssec_enabled = enabled;
        self
    }

    pub fn with_blocklist(mut self, enabled: bool) -> Self {
        self.blocklist_enabled = enabled;
        self
    }

    pub async fn build(self) -> Result<TestServer, std::io::Error> {
        let port = self.port.unwrap_or(0);
        TestServer::start_on_port(port).await
    }
}

impl Default for TestServerBuilder {
    fn default() -> Self {
        Self::new()
    }
}

pub struct TestClient {
    server_addr: SocketAddr,
}

impl TestClient {
    pub fn new(server_addr: SocketAddr) -> Self {
        Self { server_addr }
    }

    pub async fn query(&self, _domain: &str, _record_type: &str) -> Result<Vec<String>, String> {
        // TODO: Implementar query real quando disponível
        Ok(vec!["192.168.1.1".to_string()])
    }

    pub async fn query_many(&self, queries: Vec<(&str, &str)>) -> Vec<Result<Vec<String>, String>> {
        let mut results = Vec::new();
        for (domain, record_type) in queries {
            results.push(self.query(domain, record_type).await);
        }
        results
    }

    pub async fn query_parallel(&self, queries: Vec<(&str, &str)>) -> Vec<Result<Vec<String>, String>> {
        let handles: Vec<_> = queries
            .into_iter()
            .map(|(domain, record_type)| {
                let client = TestClient::new(self.server_addr);
                tokio::spawn(async move {
                    client.query(domain, record_type).await
                })
            })
            .collect();

        let mut results = Vec::new();
        for handle in handles {
            match handle.await {
                Ok(result) => results.push(result),
                Err(e) => results.push(Err(e.to_string())),
            }
        }
        results
    }
}

#[derive(Debug, Clone, Default)]
pub struct ServerMetrics {
    pub queries_total: u64,
    pub queries_blocked: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub dnssec_validated: u64,
    pub errors: u64,
}

impl ServerMetrics {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn cache_hit_rate(&self) -> f64 {
        let total = self.cache_hits + self.cache_misses;
        if total == 0 {
            0.0
        } else {
            self.cache_hits as f64 / total as f64
        }
    }

    pub fn block_rate(&self) -> f64 {
        if self.queries_total == 0 {
            0.0
        } else {
            self.queries_blocked as f64 / self.queries_total as f64
        }
    }

    pub fn error_rate(&self) -> f64 {
        if self.queries_total == 0 {
            0.0
        } else {
            self.errors as f64 / self.queries_total as f64
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_server_creation() {
        let server = TestServer::start().await;
        assert!(server.is_ok());
        
        let server = server.unwrap();
        assert!(server.port() > 0);
        
        server.shutdown();
    }

    #[tokio::test]
    async fn test_server_builder() {
        let server = TestServerBuilder::new()
            .with_port(15353)
            .with_cache(true)
            .with_dnssec(false)
            .build()
            .await;

        assert!(server.is_ok());
        let server = server.unwrap();
        assert_eq!(server.port(), 15353);
        
        server.shutdown();
    }

    #[tokio::test]
    async fn test_client_creation() {
        let addr = "127.0.0.1:15353".parse().unwrap();
        let client = TestClient::new(addr);
        
        // Should not panic
        drop(client);
    }

    #[test]
    fn test_metrics() {
        let mut metrics = ServerMetrics::new();
        assert_eq!(metrics.queries_total, 0);
        assert_eq!(metrics.cache_hit_rate(), 0.0);

        metrics.queries_total = 100;
        metrics.cache_hits = 70;
        metrics.cache_misses = 30;
        
        assert_eq!(metrics.cache_hit_rate(), 0.7);
        
        metrics.queries_blocked = 10;
        assert_eq!(metrics.block_rate(), 0.1);
    }

    #[test]
    fn test_metrics_edge_cases() {
        let metrics = ServerMetrics::new();
        
        // Division by zero should not panic
        assert_eq!(metrics.cache_hit_rate(), 0.0);
        assert_eq!(metrics.block_rate(), 0.0);
        assert_eq!(metrics.error_rate(), 0.0);
    }
}
