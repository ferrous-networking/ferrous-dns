use dashmap::DashMap;
use rustc_hash::FxBuildHasher;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::runtime::{Handle, Id as RuntimeId};
use tokio::sync::{Semaphore, SemaphorePermit};
use tracing::info;

/// Queries one source port serves before it is retired.
///
/// A pooled socket otherwise keeps its ephemeral port for the life of the
/// process, so the handful of ports an upstream ever sees is fixed. An attacker
/// who learns one — by probing the resolver for open UDP ports, or by being the
/// upstream — can reuse that knowledge indefinitely, leaving off-path forgery to
/// guess the 16-bit transaction ID alone. Rotating bounds how long a discovered
/// port stays worth anything. 1000 is often enough for that and rare enough that
/// the `socket()`/`bind()` cost stays noise next to the upstream RTT.
const PORT_ROTATION_QUERIES: u32 = 1000;

/// ±25% spread on [`PORT_ROTATION_QUERIES`], drawn per socket so the sockets of
/// one upstream do not all turn over at the same instant.
const PORT_ROTATION_JITTER: u32 = PORT_ROTATION_QUERIES / 4;

/// A socket parked in the pool, carrying the wear it has already accumulated so
/// that reuse counts survive the round trip through the pool.
struct PooledEntry {
    socket: Arc<UdpSocket>,
    uses: u32,
    budget: u32,
}

pub struct UdpSocketPool {
    /// Keyed by runtime as well as server: a tokio socket only works on the
    /// runtime that registered it. The binary runs one, but every
    /// `#[tokio::test]` has its own, and a socket parked by a finished one fails
    /// every send.
    pools: DashMap<(RuntimeId, SocketAddr), Vec<PooledEntry>, FxBuildHasher>,

    max_per_server: usize,

    semaphore: Semaphore,

    total_created: AtomicU64,
    total_retired: AtomicU64,
}

impl UdpSocketPool {
    /// Bounds idle sockets per server and simultaneous checked-out exchanges.
    pub fn new(max_per_server: usize, total_limit: usize) -> Self {
        info!(max_per_server, total_limit, "Initializing UDP socket pool");

        Self {
            pools: DashMap::with_hasher(FxBuildHasher),
            max_per_server,
            semaphore: Semaphore::new(total_limit),
            total_created: AtomicU64::new(0),
            total_retired: AtomicU64::new(0),
        }
    }

    /// Queries this socket may serve before its port is rotated out.
    fn rotation_budget() -> u32 {
        PORT_ROTATION_QUERIES - PORT_ROTATION_JITTER + fastrand::u32(0..2 * PORT_ROTATION_JITTER)
    }

    pub async fn acquire(&self, server: SocketAddr) -> Result<PooledUdpSocket<'_>, std::io::Error> {
        let permit = self
            .semaphore
            .acquire()
            .await
            .map_err(std::io::Error::other)?;

        let key = (Handle::current().id(), server);
        if let Some(mut entry) = self.pools.get_mut(&key) {
            if let Some(pooled) = entry.pop() {
                return Ok(PooledUdpSocket {
                    socket: pooled.socket,
                    uses: pooled.uses.saturating_add(1),
                    budget: pooled.budget,
                    key,
                    pool: self,
                    _permit: permit,
                    poisoned: false,
                });
            }
        }

        let socket = self.create_socket(server).await?;
        self.total_created.fetch_add(1, Ordering::Relaxed);

        Ok(PooledUdpSocket {
            socket: Arc::new(socket),
            uses: 1,
            budget: Self::rotation_budget(),
            key,
            pool: self,
            _permit: permit,
            poisoned: false,
        })
    }

    async fn create_socket(&self, server: SocketAddr) -> Result<UdpSocket, std::io::Error> {
        use socket2::{Domain, Protocol, Socket, Type};

        let (domain, bind_addr) = if server.is_ipv4() {
            (Domain::IPV4, SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)))
        } else {
            (Domain::IPV6, SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)))
        };

        // No SO_REUSEADDR: with it, Linux may hand an ephemeral port already held
        // by another pooled socket, and one of the two then never sees its answers.
        let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
        socket.set_recv_buffer_size(64 * 1024)?;
        socket.set_send_buffer_size(128 * 1024)?;
        socket.bind(&bind_addr.into())?;
        socket.set_nonblocking(true)?;

        let std_socket: std::net::UdpSocket = socket.into();
        UdpSocket::from_std(std_socket)
    }

    fn release(&self, key: (RuntimeId, SocketAddr), pooled: PooledEntry) {
        let mut entry = self.pools.entry(key).or_default();

        if entry.len() < self.max_per_server {
            entry.push(pooled);
        }
    }

    pub fn stats(&self) -> PoolStats {
        PoolStats {
            total_created: self.total_created.load(Ordering::Relaxed),
            total_retired: self.total_retired.load(Ordering::Relaxed),
            total_pooled: self.pools.iter().map(|e| e.len()).sum(),
        }
    }
}

pub struct PooledUdpSocket<'a> {
    socket: Arc<UdpSocket>,
    /// Queries served on this socket, including the one it was acquired for.
    uses: u32,
    /// Use count at which this socket's port is retired rather than pooled.
    budget: u32,
    key: (RuntimeId, SocketAddr),
    pool: &'a UdpSocketPool,
    _permit: SemaphorePermit<'a>,
    poisoned: bool,
}

impl<'a> PooledUdpSocket<'a> {
    pub fn socket(&self) -> &UdpSocket {
        &self.socket
    }

    pub fn server(&self) -> SocketAddr {
        self.key.1
    }

    pub fn poison(&mut self) {
        self.poisoned = true;
    }
}

impl<'a> Drop for PooledUdpSocket<'a> {
    fn drop(&mut self) {
        if self.poisoned {
            return;
        }
        // Dropping instead of parking retires the source port: the next acquire
        // binds a fresh one. See PORT_ROTATION_QUERIES.
        if self.uses >= self.budget {
            self.pool.total_retired.fetch_add(1, Ordering::Relaxed);
            return;
        }
        self.pool.release(
            self.key,
            PooledEntry {
                socket: self.socket.clone(),
                uses: self.uses,
                budget: self.budget,
            },
        );
    }
}

#[derive(Debug, Clone)]
pub struct PoolStats {
    pub total_created: u64,

    /// Sockets dropped on release because their port hit the rotation budget.
    pub total_retired: u64,

    pub total_pooled: usize,
}
