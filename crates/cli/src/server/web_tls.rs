use axum::Router;
use hyper::body::Incoming;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, warn};

/// Runs the web server over HTTPS with automatic HTTP → HTTPS redirect.
///
/// On each accepted TCP connection the first byte is peeked:
/// - `0x16` (TLS ClientHello) → proceed with TLS handshake and serve normally.
/// - Anything else (plain HTTP) → respond with 301 redirect to `https://`.
///
/// This allows the same port to handle both protocols transparently.
pub(super) async fn start_https_web_server(
    bind_addr: SocketAddr,
    app: Router,
    tls_config: Arc<rustls::ServerConfig>,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind(bind_addr).await?;
    let acceptor = TlsAcceptor::from(tls_config);

    loop {
        let (stream, peer_addr) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                error!(error = %e, "HTTPS accept error");
                continue;
            }
        };

        let acceptor = acceptor.clone();
        let tower_service = app.clone();
        let port = bind_addr.port();

        tokio::spawn(async move {
            let mut peek_buf = [0u8; 1];
            match stream.peek(&mut peek_buf).await {
                Ok(0) => return,
                Ok(_) => {}
                Err(e) => {
                    debug!(client = %peer_addr, error = %e, "Peek error");
                    return;
                }
            }

            if peek_buf[0] != 0x16 {
                send_https_redirect(stream, peer_addr, port).await;
                return;
            }

            let tls_stream = match acceptor.accept(stream).await {
                Ok(s) => s,
                Err(e) => {
                    warn!(client = %peer_addr, error = %e, "TLS handshake failed");
                    return;
                }
            };

            let io = TokioIo::new(tls_stream);

            let hyper_svc = hyper::service::service_fn(move |req: hyper::Request<Incoming>| {
                let mut svc = tower_service.clone();
                async move {
                    use tower::Service;
                    let (parts, body) = req.into_parts();
                    let req = hyper::Request::from_parts(parts, axum::body::Body::new(body));
                    svc.call(req).await
                }
            });

            if let Err(e) = Builder::new(TokioExecutor::new())
                .serve_connection(io, hyper_svc)
                .await
            {
                debug!(client = %peer_addr, error = %e, "HTTPS connection error");
            }
        });
    }
}

/// Reads the incoming HTTP request line to extract the path, then sends a
/// 301 redirect to `https://<Host>:<port><path>`.
async fn send_https_redirect(mut stream: TcpStream, peer_addr: SocketAddr, port: u16) {
    let mut buf = [0u8; 1024];
    let n = match tokio::time::timeout(
        std::time::Duration::from_secs(5),
        tokio::io::AsyncReadExt::read(&mut stream, &mut buf),
    )
    .await
    {
        Ok(Ok(n)) if n > 0 => n,
        _ => return,
    };

    let request = String::from_utf8_lossy(&buf[..n]);

    let host = extract_host(&request).unwrap_or_else(|| peer_addr.ip().to_string());
    let path = extract_path(&request).unwrap_or("/");

    let location = if port == 443 {
        format!("https://{host}{path}")
    } else {
        format!("https://{host}:{port}{path}")
    };

    let response = format!(
        "HTTP/1.1 301 Moved Permanently\r\n\
         Location: {location}\r\n\
         Content-Length: 0\r\n\
         Connection: close\r\n\r\n"
    );

    let _ = stream.write_all(response.as_bytes()).await;
    debug!(client = %peer_addr, location, "HTTP → HTTPS redirect");
}

/// Extracts the request path from an HTTP request line (e.g. `GET /foo HTTP/1.1`).
fn extract_path(request: &str) -> Option<&str> {
    let first_line = request.lines().next()?;
    let mut parts = first_line.split_whitespace();
    parts.next()?; // method
    let path = parts.next()?;
    Some(path)
}

/// Extracts the `Host` header value from raw HTTP headers.
fn extract_host(request: &str) -> Option<String> {
    for line in request.lines().skip(1) {
        if line.is_empty() {
            break;
        }
        if let Some(value) = line
            .strip_prefix("Host:")
            .or_else(|| line.strip_prefix("host:"))
        {
            let host = value.trim();
            // Strip port from Host header (we'll add the HTTPS port ourselves)
            return Some(host.split(':').next().unwrap_or(host).to_string());
        }
    }
    None
}
