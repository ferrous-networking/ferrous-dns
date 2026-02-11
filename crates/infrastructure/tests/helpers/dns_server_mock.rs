#![allow(dead_code)]
use std::net::SocketAddr;
use tokio::net::UdpSocket;
use tokio::sync::oneshot;

/// Mock de servidor DNS para testes
///
/// Este servidor simples responde a queries DNS com respostas predefinidas.
/// Útil para testes que não dependem de DNS real.
pub struct MockDnsServer {
    addr: SocketAddr,
    shutdown_tx: Option<oneshot::Sender<()>>,
}

impl MockDnsServer {
    /// Inicia um servidor mock na porta especificada
    ///
    /// Retorna o servidor e o endereço real onde está escutando
    pub async fn start(port: u16) -> Result<(Self, SocketAddr), std::io::Error> {
        let addr = SocketAddr::from(([127, 0, 0, 1], port));
        let socket = UdpSocket::bind(addr).await?;
        let local_addr = socket.local_addr()?;

        let (shutdown_tx, mut shutdown_rx) = oneshot::channel();

        // Spawn servidor em background
        tokio::spawn(async move {
            let mut buf = vec![0u8; 512];

            loop {
                tokio::select! {
                    _ = &mut shutdown_rx => {
                        break;
                    }
                    result = socket.recv_from(&mut buf) => {
                        if let Ok((len, peer)) = result {
                            // Resposta DNS mock simples
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

    /// Endereço do servidor
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Cria uma resposta DNS mock simples
    fn build_mock_response(query: &[u8]) -> Vec<u8> {
        if query.len() < 12 {
            return vec![];
        }

        let mut response = Vec::with_capacity(512);

        // Copia header da query
        response.extend_from_slice(&query[0..2]); // Transaction ID

        // Flags: QR=1 (response), RD=1, RA=1
        response.push(0x81); // QR=1, Opcode=0, AA=0, TC=0, RD=1
        response.push(0x80); // RA=1, Z=0, RCODE=0

        // Questions count (from query)
        response.extend_from_slice(&query[4..6]);

        // Answers count: 1
        response.extend_from_slice(&[0x00, 0x01]);

        // Authority RRs: 0
        response.extend_from_slice(&[0x00, 0x00]);

        // Additional RRs: 0
        response.extend_from_slice(&[0x00, 0x00]);

        // Copy question section (rest of query)
        if query.len() > 12 {
            response.extend_from_slice(&query[12..]);
        }

        // Answer section (mock A record: 93.184.216.34)
        response.extend_from_slice(&[
            0xc0, 0x0c, // Name pointer to question
            0x00, 0x01, // Type A
            0x00, 0x01, // Class IN
            0x00, 0x00, 0x00, 0x3c, // TTL: 60 seconds
            0x00, 0x04, // Data length: 4 bytes
            93, 184, 216, 34, // IP: 93.184.216.34
        ]);

        response
    }

    /// Para o servidor
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

        // Cria um socket cliente
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        // Query DNS simples (só header + question mínimo)
        let query = vec![
            0x12, 0x34, // ID
            0x01, 0x00, // Flags: recursion desired
            0x00, 0x01, // Questions: 1
            0x00, 0x00, // Answers: 0
            0x00, 0x00, // Authority: 0
            0x00, 0x00, // Additional: 0
        ];

        // Envia query
        client.send_to(&query, addr).await.unwrap();

        // Recebe resposta
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
            0xab, 0xcd, // ID
            0x01, 0x00, // Flags
            0x00, 0x01, // Questions
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Counts
        ];

        let response = MockDnsServer::build_mock_response(&query);

        assert!(response.len() > 12);
        assert_eq!(response[0..2], [0xab, 0xcd]); // Same ID
        assert_eq!(response[2], 0x81); // Response flag set
    }
}
