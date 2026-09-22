mod common;

use axum::body::{to_bytes, Body};
use ferrous_dns_domain::DnsProtocol;
use ferrous_dns_infrastructure::dns::transport::get_or_create_transport;
use hyper::{Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::convert::Infallible;
use std::net::{Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;

async fn serve_answer(listener: TcpListener, answer: &'static [u8]) {
    let (stream, _) = listener.accept().await.unwrap();
    let service =
        hyper::service::service_fn(move |request: Request<hyper::body::Incoming>| async move {
            to_bytes(Body::new(request.into_body()), 65_535)
                .await
                .unwrap();
            Ok::<_, Infallible>(Response::new(Body::from(answer)))
        });
    let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
        .serve_connection(TokioIo::new(stream), service)
        .await;
}

#[test]
fn test_doh_reloaded_addresses_do_not_reuse_previous_endpoint() {
    const CHILD: &str = "FERROUS_TEST_DOH_ADDRESS_RELOAD";
    if std::env::var_os(CHILD).is_none() {
        // Isolate proxy environment changes from concurrently running tests.
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "test_doh_reloaded_addresses_do_not_reuse_previous_endpoint",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .env("NO_PROXY", "*")
            .env("no_proxy", "*")
            .status()
            .unwrap();
        assert!(status.success());
        return;
    }

    if !common::dual_stack_loopback_available() {
        return;
    }
    ferrous_dns::install_crypto_provider();
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let first_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let first_addr = first_listener.local_addr().unwrap();
            let second_addr = SocketAddr::from((Ipv6Addr::LOCALHOST, first_addr.port()));
            let second_listener = TcpListener::bind(second_addr).await.unwrap();
            tokio::spawn(serve_answer(first_listener, b"first endpoint"));
            tokio::spawn(serve_answer(second_listener, b"second endpoint"));

            let hostname: Arc<str> = Arc::from("doh-reload.invalid");
            let url: Arc<str> =
                Arc::from(format!("http://{hostname}:{}/dns-query", first_addr.port()));
            let protocol = |addr| DnsProtocol::Https {
                url: url.clone(),
                hostname: hostname.clone(),
                resolved_addrs: vec![addr],
            };
            let first = get_or_create_transport(&protocol(first_addr)).unwrap();
            let reloaded = get_or_create_transport(&protocol(second_addr)).unwrap();
            for (transport, expected) in [
                (&first, b"first endpoint".as_slice()),
                (&reloaded, b"second endpoint".as_slice()),
                (&first, b"first endpoint".as_slice()),
            ] {
                let response = transport
                    .send(&[0; 12], Duration::from_secs(5))
                    .await
                    .unwrap();
                assert_eq!(response.bytes.as_ref(), expected);
            }
        });
}
