use super::connection_limiter::{ConnectionGuard, ConnectionLimiter};
use super::pktinfo;
use ferrous_dns_infrastructure::dns::server::DnsServerHandler;
use quinn::crypto::rustls::QuicServerConfig;
use quinn::VarInt;
use socket2::{Domain, Protocol, Socket, Type};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info, warn};

/// Idle keep-alive interval for accepted DoQ connections.
const DOQ_KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(15);

/// Upper bound on concurrent in-flight queries (bidirectional streams) per
/// connection. The per-IP `ConnectionLimiter` caps how many connections a
/// client may open; this caps how many streams each connection may multiplex,
/// so a single connection cannot open unbounded streams.
const DOQ_MAX_CONCURRENT_BIDI_STREAMS: u32 = 100;

/// How long a stream may take to deliver its length-prefixed query before it is
/// dropped. Guards against a client that opens a stream and then stalls
/// (slow-loris), which QUIC keep-alive would otherwise leave lingering.
const DOQ_STREAM_READ_TIMEOUT: Duration = Duration::from_secs(5);

/// Builds and binds a QUIC server endpoint for DoQ (DNS-over-QUIC, RFC 9250)
/// on `bind_addr`, advertising whatever ALPN the supplied `tls_config` carries
/// (the caller sets `doq`). Binding is synchronous, so the returned endpoint is
/// ready to accept connections immediately.
///
/// Like the Do53 and DoT listeners, the socket is always AF_INET6 with
/// `only_v6` off: an IPv4 `bind_addr` is bound in v4-mapped form and keeps its
/// v4-only behaviour, while `[::]` serves both families on one socket.
pub fn bind_doq_endpoint(
    bind_addr: &str,
    tls_config: Arc<rustls::ServerConfig>,
) -> anyhow::Result<quinn::Endpoint> {
    let addr = pktinfo::v6_mapped_bind_addr(bind_addr.parse()?);
    let quic_crypto = QuicServerConfig::try_from(tls_config)?;
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_crypto));
    // A freshly built ServerConfig uniquely owns its transport config, so this
    // never no-ops; expect() surfaces the invariant instead of silently
    // skipping the transport tuning below.
    let transport_config = Arc::get_mut(&mut server_config.transport)
        .expect("fresh quinn ServerConfig has a uniquely-owned transport config");
    transport_config.keep_alive_interval(Some(DOQ_KEEP_ALIVE_INTERVAL));
    transport_config.max_concurrent_bidi_streams(VarInt::from_u32(DOQ_MAX_CONCURRENT_BIDI_STREAMS));

    let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_only_v6(false)?;
    socket.bind(&addr.into())?;
    socket.set_nonblocking(true)?;
    let runtime = quinn::default_runtime()
        .ok_or_else(|| anyhow::anyhow!("no async runtime available for the DoQ endpoint"))?;
    Ok(quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        Some(server_config),
        socket.into(),
        runtime,
    )?)
}

pub async fn start_doq_server(
    bind_addr: String,
    handler: Arc<DnsServerHandler>,
    tls_config: Arc<rustls::ServerConfig>,
    doq_conn_limiter: ConnectionLimiter,
) -> anyhow::Result<()> {
    let endpoint = bind_doq_endpoint(&bind_addr, tls_config)?;
    // `local_addr` reports the v4-mapped form of an IPv4 bind; report the
    // address the operator configured.
    let local_addr = pktinfo::unmap_socket_addr(endpoint.local_addr()?);
    info!(bind_address = %local_addr, "Starting DoQ server (DNS-over-QUIC, RFC 9250)");
    serve_doq(endpoint, handler, doq_conn_limiter).await;
    Ok(())
}

/// Runs the accept loop for an already-bound DoQ endpoint. Split from
/// `start_doq_server` so tests can bind on an ephemeral port, read the resolved
/// address, and drive the loop without a bind race.
pub async fn serve_doq(
    endpoint: quinn::Endpoint,
    handler: Arc<DnsServerHandler>,
    doq_conn_limiter: ConnectionLimiter,
) {
    while let Some(incoming) = endpoint.accept().await {
        // A dual-stack endpoint reports IPv4 peers as `::ffff:a.b.c.d`;
        // normalise so limits, groups, and logs see real IPv4.
        let peer_addr = pktinfo::unmap_socket_addr(incoming.remote_address());
        let guard = match doq_conn_limiter.try_acquire(peer_addr.ip()) {
            Some(g) => g,
            None => {
                debug!(client = %peer_addr, "DoQ connection rejected: per-IP limit");
                incoming.refuse();
                continue;
            }
        };
        tokio::spawn(handle_doq_connection(incoming, handler.clone(), guard));
    }
}

async fn handle_doq_connection(
    incoming: quinn::Incoming,
    handler: Arc<DnsServerHandler>,
    _guard: ConnectionGuard,
) {
    let peer_addr = pktinfo::unmap_socket_addr(incoming.remote_address());

    let connection = match incoming.await {
        Ok(c) => c,
        Err(e) => {
            warn!(client = %peer_addr, error = %e, "DoQ handshake failed");
            return;
        }
    };

    debug!(client = %peer_addr, "DoQ connection accepted");
    let client_ip = pktinfo::unmap_socket_addr(connection.remote_address()).ip();

    loop {
        let (send_stream, recv_stream) = match connection.accept_bi().await {
            Ok(streams) => streams,
            Err(quinn::ConnectionError::ApplicationClosed(_)) => break,
            Err(e) => {
                debug!(client = %peer_addr, error = %e, "DoQ connection error");
                break;
            }
        };
        tokio::spawn(handle_doq_stream(
            send_stream,
            recv_stream,
            handler.clone(),
            client_ip,
        ));
    }

    debug!(client = %peer_addr, "DoQ connection closed");
}

async fn handle_doq_stream(
    mut send_stream: quinn::SendStream,
    mut recv_stream: quinn::RecvStream,
    handler: Arc<DnsServerHandler>,
    client_ip: IpAddr,
) {
    let mut len_buf = [0u8; 2];
    if !read_exact_within_timeout(&mut recv_stream, &mut len_buf).await {
        return;
    }
    let msg_len = u16::from_be_bytes(len_buf) as usize;
    if msg_len == 0 {
        return;
    }

    let mut dns_buf = vec![0u8; msg_len];
    if !read_exact_within_timeout(&mut recv_stream, &mut dns_buf).await {
        return;
    }

    if let Some(resp) = handler
        .handle_raw_udp_fallback(&dns_buf, client_ip, false)
        .await
    {
        let resp_len = (resp.len() as u16).to_be_bytes();
        if send_stream.write_all(&resp_len).await.is_err() {
            return;
        }
        if send_stream.write_all(&resp).await.is_err() {
            return;
        }
    }

    // A finish() error here means the peer already reset/closed the stream —
    // a benign client-side condition, so log at debug like the other drop paths.
    if let Err(e) = send_stream.finish() {
        debug!(error = %e, "DoQ send stream finish skipped (peer already closed)");
    }
}

/// Reads exactly `buf.len()` bytes from `recv_stream`, giving up (returning
/// `false`) on read error, EOF, or if `DOQ_STREAM_READ_TIMEOUT` elapses first.
async fn read_exact_within_timeout(recv_stream: &mut quinn::RecvStream, buf: &mut [u8]) -> bool {
    matches!(
        tokio::time::timeout(DOQ_STREAM_READ_TIMEOUT, recv_stream.read_exact(buf)).await,
        Ok(Ok(()))
    )
}
