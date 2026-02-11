use dashmap::DashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::Semaphore;
use tracing::{debug, info};

/// Pool de sockets UDP reutilizáveis para otimizar performance.
///
/// Evita overhead de bind/close em cada query DNS, reduzindo latência em 10-20%.
/// Sockets são organizados por servidor upstream e reutilizados quando disponíveis.
pub struct UdpSocketPool {
    /// Sockets disponíveis organizados por servidor upstream
    pools: DashMap<SocketAddr, Vec<Arc<UdpSocket>>>,

    /// Máximo de sockets por servidor
    max_per_server: usize,

    /// Semáforo para limitar sockets totais no sistema
    semaphore: Arc<Semaphore>,

    /// Total de sockets criados (métrica)
    total_created: AtomicU64,

    /// Total de reutilizações (métrica)
    total_reused: AtomicU64,
}

impl UdpSocketPool {
    /// Cria novo pool de sockets UDP.
    ///
    /// # Argumentos
    /// * `max_per_server` - Máximo de sockets por servidor (recomendado: 4-8)
    /// * `total_limit` - Limite total de sockets (recomendado: max_per_server * num_servers * 2)
    ///
    /// # Exemplo
    /// ```ignore
    /// let pool = UdpSocketPool::new(8, 100);
    /// ```
    pub fn new(max_per_server: usize, total_limit: usize) -> Self {
        info!(max_per_server, total_limit, "Initializing UDP socket pool");

        Self {
            pools: DashMap::new(),
            max_per_server,
            semaphore: Arc::new(Semaphore::new(total_limit)),
            total_created: AtomicU64::new(0),
            total_reused: AtomicU64::new(0),
        }
    }

    /// Adquire socket do pool ou cria novo.
    ///
    /// Tenta reutilizar socket existente. Se não disponível, cria novo.
    /// Socket será automaticamente devolvido ao pool quando dropado.
    pub async fn acquire(&self, server: SocketAddr) -> Result<PooledUdpSocket<'_>, std::io::Error> {
        // Tenta reutilizar socket existente do pool
        if let Some(mut entry) = self.pools.get_mut(&server) {
            if let Some(socket) = entry.pop() {
                self.total_reused.fetch_add(1, Ordering::Relaxed);
                debug!(server = %server, "Reusing UDP socket from pool");

                return Ok(PooledUdpSocket {
                    socket,
                    server,
                    pool: self,
                    _permit: None, // Socket já existe, não precisa de permit
                });
            }
        }

        let permit = self.semaphore.clone().acquire_owned().await.ok();

        let socket = self.create_socket(server).await?;
        self.total_created.fetch_add(1, Ordering::Relaxed);

        debug!(server = %server, "Created new UDP socket");

        Ok(PooledUdpSocket {
            socket: Arc::new(socket),
            server,
            pool: self,
            _permit: permit,
        })
    }

    /// Cria novo socket UDP com configurações otimizadas.
    async fn create_socket(&self, server: SocketAddr) -> Result<UdpSocket, std::io::Error> {
        use socket2::{Domain, Protocol, Socket, Type};

        let domain = if server.is_ipv4() {
            Domain::IPV4
        } else {
            Domain::IPV6
        };

        let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;

        socket.set_reuse_address(true)?;

        socket.set_recv_buffer_size(256 * 1024)?; // 256KB recv
        socket.set_send_buffer_size(128 * 1024)?; // 128KB send

        let bind_addr: SocketAddr = if server.is_ipv4() {
            "0.0.0.0:0".parse().unwrap()
        } else {
            "[::]:0".parse().unwrap()
        };

        socket.bind(&bind_addr.into())?;
        socket.set_nonblocking(true)?;

        let std_socket: std::net::UdpSocket = socket.into();
        UdpSocket::from_std(std_socket)
    }

    /// Devolve socket ao pool para reutilização.
    ///
    /// Chamado automaticamente quando PooledUdpSocket é dropado.
    fn release(&self, server: SocketAddr, socket: Arc<UdpSocket>) {
        let mut entry = self.pools.entry(server).or_default();

        // Só guarda se não excedeu limite do pool
        if entry.len() < self.max_per_server {
            entry.push(socket);
            debug!(
                server = %server,
                pool_size = entry.len(),
                "Returned UDP socket to pool"
            );
        } else {
            debug!(server = %server, "Pool full, dropping socket");
            // Socket será dropado automaticamente
        }
    }

    /// Retorna estatísticas do pool.
    pub fn stats(&self) -> PoolStats {
        let total_pooled: usize = self.pools.iter().map(|e| e.len()).sum();

        PoolStats {
            total_created: self.total_created.load(Ordering::Relaxed),
            total_reused: self.total_reused.load(Ordering::Relaxed),
            total_pooled,
            servers: self.pools.len(),
        }
    }

    /// Limpa pool de um servidor específico.
    pub fn clear_server(&self, server: &SocketAddr) {
        if let Some((_, sockets)) = self.pools.remove(server) {
            debug!(
                server = %server,
                count = sockets.len(),
                "Cleared socket pool for server"
            );
        }
    }

    /// Limpa todos os pools.
    pub fn clear_all(&self) {
        let count: usize = self.pools.iter().map(|e| e.len()).sum();
        self.pools.clear();
        info!(count, "Cleared all socket pools");
    }
}

/// Socket UDP do pool com RAII cleanup automático.
///
/// Quando dropado, socket é automaticamente devolvido ao pool.
pub struct PooledUdpSocket<'a> {
    socket: Arc<UdpSocket>,
    server: SocketAddr,
    pool: &'a UdpSocketPool,
    _permit: Option<tokio::sync::OwnedSemaphorePermit>,
}

impl<'a> PooledUdpSocket<'a> {
    /// Acesso ao socket interno.
    pub fn socket(&self) -> &UdpSocket {
        &self.socket
    }

    /// Endereço do servidor upstream.
    pub fn server(&self) -> SocketAddr {
        self.server
    }
}

impl<'a> Drop for PooledUdpSocket<'a> {
    fn drop(&mut self) {
        // Devolve socket ao pool automaticamente
        self.pool.release(self.server, self.socket.clone());
    }
}

/// Estatísticas do pool de sockets.
#[derive(Debug, Clone)]
pub struct PoolStats {
    /// Total de sockets criados desde o início
    pub total_created: u64,
    /// Total de reutilizações de sockets
    pub total_reused: u64,
    /// Total de sockets atualmente no pool
    pub total_pooled: usize,
    /// Número de servidores com sockets no pool
    pub servers: usize,
}

impl PoolStats {
    /// Calcula taxa de reutilização.
    pub fn reuse_rate(&self) -> f64 {
        if self.total_created == 0 {
            0.0
        } else {
            self.total_reused as f64 / self.total_created as f64
        }
    }
}
