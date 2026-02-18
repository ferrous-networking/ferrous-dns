#![allow(dead_code)]
use std::net::SocketAddr;
use tokio::net::UdpSocket;
use tokio::sync::oneshot;

pub struct MockDnsServer {
    addr: SocketAddr,
    shutdown_tx: Option<oneshot::Sender<()>>,
}

impl MockDnsServer {
    
    pub async fn start(port: u16) -> Result<(Self, SocketAddr), std::io::Error> {
        let addr = SocketAddr::from(([127, 0, 0, 1], port));
        let socket = UdpSocket::bind(addr).await?;
        let local_addr = socket.local_addr()?;

        let (shutdown_tx, mut shutdown_rx) = oneshot::channel();

        tokio::spawn(async move {
            let mut buf = vec![0u8; 512];

            loop {
                tokio::select! {
                    _ = &mut shutdown_rx => {
                        break;
                    }
                    result = socket.recv_from(&mut buf) => {
                        if let Ok((len, peer)) = result {
                            
                            let response = Self::build_mock_response(&buf[..len]);
                            let _ = socket.send_to(&response, peer).await;
                        }
                    }
                }
            }
        });

        Ok((
            Self {
                addr: local_addr,
                shutdown_tx: Some(shutdown_tx),
            },
            local_addr,
        ))
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    fn build_mock_response(query: &[u8]) -> Vec<u8> {
        if query.len() < 12 {
            return vec![];
        }

        let mut response = Vec::with_capacity(512);

        response.extend_from_slice(&query[0..2]); 

        response.push(0x81); 
        response.push(0x80); 

        response.extend_from_slice(&query[4..6]);

        response.extend_from_slice(&[0x00, 0x01]);

        response.extend_from_slice(&[0x00, 0x00]);

        response.extend_from_slice(&[0x00, 0x00]);

        if query.len() > 12 {
            response.extend_from_slice(&query[12..]);
        }

        response.extend_from_slice(&[
            0xc0, 0x0c, 
            0x00, 0x01, 
            0x00, 0x01, 
            0x00, 0x00, 0x00, 0x3c, 
            0x00, 0x04, 
            93, 184, 216, 34, 
        ]);

        response
    }

    pub fn shutdown(mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
    }
}

impl Drop for MockDnsServer {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_mock_server_starts() {
        let result = MockDnsServer::start(15353).await;
        assert!(result.is_ok());

        let (server, addr) = result.unwrap();
        assert_eq!(addr.port(), 15353);

        server.shutdown();
    }

    #[tokio::test]
    async fn test_mock_server_responds() {
        let (server, addr) = MockDnsServer::start(15354).await.unwrap();

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        let query = vec![
            0x12, 0x34, 
            0x01, 0x00, 
            0x00, 0x01, 
            0x00, 0x00, 
            0x00, 0x00, 
            0x00, 0x00, 
        ];

        client.send_to(&query, addr).await.unwrap();

        let mut buf = vec![0u8; 512];
        let (len, _) = client.recv_from(&mut buf).await.unwrap();

        assert!(len > 12, "Response should have at least header");
        assert_eq!(buf[0..2], query[0..2], "Transaction ID should match");
        assert_eq!(buf[2] & 0x80, 0x80, "QR bit should be set (response)");

        server.shutdown();
    }

    #[test]
    fn test_mock_response_builder() {
        let query = vec![
            0xab, 0xcd, 
            0x01, 0x00, 
            0x00, 0x01, 
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        ];

        let response = MockDnsServer::build_mock_response(&query);

        assert!(response.len() > 12);
        assert_eq!(response[0..2], [0xab, 0xcd]); 
        assert_eq!(response[2], 0x81); 
    }
}
