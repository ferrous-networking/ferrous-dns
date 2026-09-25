//! Downloads of blocklist and allowlist sources, issue #248.
//!
//! HaGeZi's Threat Intelligence Feeds list is 44 MB, so on a link slower than
//! about 12 Mbit/s it cannot arrive within 30 seconds. A cap on the whole
//! transfer dropped it on every sync while the rebuild still reported success.
//! Only a transfer that stops making progress should fail, and the error has
//! to say it timed out. The clock is paused, so a simulated minute is free.

use ferrous_dns_infrastructure::dns::block_filter::ListDownloader;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::time::{sleep, Duration, Instant};

/// Keeps a timer due every 10 ms. A paused clock auto-advances straight to the
/// next due timer whenever the runtime idles, so without this it would jump to
/// the client's timeout while loopback I/O is still in flight.
fn keep_clock_ticking() {
    tokio::spawn(async {
        loop {
            sleep(Duration::from_millis(10)).await;
        }
    });
}

/// Serves one `200 OK` that declares `declared_len` bytes, then writes
/// `chunks` with a pause of `gap` after each. When the chunks fall short of
/// the declared length the connection is held open rather than closed.
async fn serve_in_chunks(chunks: Vec<String>, gap: Duration, declared_len: usize) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/list.txt", listener.local_addr().unwrap());
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        loop {
            line.clear();
            assert_ne!(reader.read_line(&mut line).await.unwrap(), 0);
            if line == "\r\n" {
                break;
            }
        }
        let mut stream = reader.into_inner();
        let head = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {declared_len}\r\nConnection: close\r\n\r\n"
        );
        stream.write_all(head.as_bytes()).await.unwrap();
        for chunk in chunks {
            if stream.write_all(chunk.as_bytes()).await.is_err() {
                return;
            }
            sleep(gap).await;
        }
        sleep(Duration::from_secs(3600)).await;
    });
    url
}

fn list_lines(count: usize) -> Vec<String> {
    (0..count).map(|i| format!("||slow-{i}.test^\n")).collect()
}

#[tokio::test(start_paused = true)]
async fn a_slow_download_that_keeps_making_progress_completes() {
    keep_clock_ticking();
    // Ten lines five seconds apart: 45 seconds end to end, never idle for long.
    let chunks = list_lines(10);
    let body = chunks.concat();
    let url = serve_in_chunks(chunks, Duration::from_secs(5), body.len()).await;

    let text = ListDownloader::new()
        .unwrap()
        .fetch(&url)
        .await
        .expect("a download that keeps making progress must complete");

    assert_eq!(text, body);
}

#[tokio::test(start_paused = true)]
async fn a_stalled_download_fails_with_a_timeout_error() {
    keep_clock_ticking();
    let url = serve_in_chunks(list_lines(1), Duration::ZERO, 1024).await;

    let started = Instant::now();
    let error = ListDownloader::new()
        .unwrap()
        .fetch(&url)
        .await
        .expect_err("a download that stops sending must fail");

    assert!(
        error.to_string().contains("timed out"),
        "the error must say the download timed out: {error}"
    );
    assert!(
        started.elapsed() < Duration::from_secs(60),
        "a stall must fail without waiting for the overall download limit"
    );
}

#[tokio::test(start_paused = true)]
async fn a_download_that_never_finishes_is_cut_off() {
    keep_clock_ticking();
    // A line every 20 seconds never trips the stall timeout, so only the
    // overall limit can end it.
    let url = serve_in_chunks(list_lines(1000), Duration::from_secs(20), 1 << 30).await;

    let started = Instant::now();
    let error = ListDownloader::new()
        .unwrap()
        .fetch(&url)
        .await
        .expect_err("a download that never finishes must be cut off");

    assert!(
        error.to_string().contains("timed out"),
        "the error must say the download timed out: {error}"
    );
    assert!(
        started.elapsed() < Duration::from_secs(10 * 60),
        "a trickling server must not hold the rebuild indefinitely"
    );
}
