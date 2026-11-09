use axum::{extract::ConnectInfo, Router};
use hyper::body::Incoming;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder;
use std::net::{IpAddr, SocketAddr};
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
    listener: TcpListener,
    app: Router,
    tls_config: Arc<rustls::ServerConfig>,
) -> anyhow::Result<()> {
    let acceptor = TlsAcceptor::from(tls_config);
    let port = listener.local_addr()?.port();

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
                    let (mut parts, body) = req.into_parts();
                    // Same peer address `axum::serve` exposes on the plain-HTTP path.
                    parts.extensions.insert(ConnectInfo(peer_addr));
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

    let host = match extract_host(&request) {
        Some(host) => host.to_owned(),
        // No usable Host header: name the address the client connected to.
        None => match stream.local_addr() {
            Ok(local) => match local.ip().to_canonical() {
                IpAddr::V6(v6) => format!("[{v6}]"),
                IpAddr::V4(v4) => v4.to_string(),
            },
            Err(_) => return,
        },
    };
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

/// Extracts the host of the `Host` header, without its port (the caller adds
/// the HTTPS one). `None` when absent or when the value holds characters no
/// host can, since it is reflected into the `Location` header.
fn extract_host(request: &str) -> Option<&str> {
    let value = request
        .lines()
        .skip(1)
        .take_while(|line| !line.is_empty())
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("host").then_some(value.trim())
        })?;
    let host = if value.starts_with('[') {
        // A bracketed IPv6 literal: its colons are not the port separator.
        &value[..=value.find(']')?]
    } else {
        value.split_once(':').map_or(value, |(host, _port)| host)
    };
    let well_formed = !host.is_empty()
        && host.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b':' | b'%' | b'[' | b']')
        });
    well_formed.then_some(host)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    fn request_with_host(host_line: &str) -> String {
        format!("GET /queries.html HTTP/1.1\r\n{host_line}\r\nAccept: */*\r\n\r\n")
    }

    #[test]
    fn extract_host_strips_the_port() {
        let request = request_with_host("Host: dns.example:8080");
        assert_eq!(extract_host(&request), Some("dns.example"));
    }

    #[test]
    fn extract_host_keeps_bracketed_ipv6_literals_whole() {
        let request = request_with_host("Host: [fe80::1]:8080");
        assert_eq!(extract_host(&request), Some("[fe80::1]"));
        let request = request_with_host("Host: [2001:db8::1]");
        assert_eq!(extract_host(&request), Some("[2001:db8::1]"));
    }

    #[test]
    fn extract_host_matches_the_header_name_case_insensitively() {
        let request = request_with_host("HOST: dns.example");
        assert_eq!(extract_host(&request), Some("dns.example"));
    }

    #[test]
    fn extract_host_rejects_values_that_could_inject_headers() {
        let request = request_with_host("Host: dns.example\rSet-Cookie: x=1");
        assert_eq!(extract_host(&request), None);
        let request = request_with_host("Host: [::1");
        assert_eq!(extract_host(&request), None);
    }

    #[tokio::test]
    async fn redirect_without_host_names_the_local_address_not_the_client() {
        let Ok(listener) = TcpListener::bind("127.0.0.2:0").await else {
            eprintln!("skipping: 127.0.0.2 is not routable here");
            return;
        };
        let server = listener.local_addr().unwrap();
        let client = tokio::net::TcpSocket::new_v4().unwrap();
        client.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let mut client = client.connect(server).await.unwrap();
        let (stream, peer) = listener.accept().await.unwrap();

        client.write_all(b"GET /x HTTP/1.0\r\n\r\n").await.unwrap();
        send_https_redirect(stream, peer, 8443).await;
        let mut response = String::new();
        client.read_to_string(&mut response).await.unwrap();

        assert!(
            response.contains("Location: https://127.0.0.2:8443/x\r\n"),
            "{response}"
        );
    }
}
