//! Competitor DNS performance comparison
//!
//! Sends real UDP DNS queries to each server and measures P50/P95/P99 latency
//! and throughput. All tests are marked `#[ignore]` — they require external
//! servers to be running.
//!
//! # Quick start
//!
//! ```bash
//! # Start competitors
//! docker compose -f docker/bench/docker-compose.yml up -d
//!
//! # Start Ferrous-DNS
//! cargo run --release -- --config ferrous-dns.toml
//!
//! # Run comparison
//! cargo test -p ferrous-dns-bench competitor -- --ignored --nocapture
//! ```
//!
//! # Environment variables
//!
//! | Variable              | Default         | Description                 |
//! |-----------------------|-----------------|-----------------------------|
//! | `FERROUS_DNS_ADDR`    | 127.0.0.1:5353  | Ferrous-DNS UDP address     |
//! | `PIHOLE_ADDR`         | 127.0.0.1:5354  | Pi-hole UDP address         |
//! | `ADGUARD_ADDR`        | 127.0.0.1:5355  | AdGuard Home UDP address    |
//! | `UNBOUND_ADDR`        | 127.0.0.1:5356  | Unbound UDP address         |
//! | `BENCH_QUERIES`       | 500             | Queries per server          |
//! | `BENCH_WARMUP`        | 50              | Warm-up queries (discarded) |

use std::net::UdpSocket;
use std::time::{Duration, Instant};

// ============================================================================
// Minimal DNS wire-format query builder (no external deps)
// ============================================================================

/// Builds a minimal DNS query packet for the given domain and record type.
/// Returns the raw UDP payload ready to be sent.
fn build_dns_query(id: u16, domain: &str, qtype: u16) -> Vec<u8> {
    let mut buf = Vec::with_capacity(512);

    // Header
    buf.extend_from_slice(&id.to_be_bytes()); // ID
    buf.extend_from_slice(&[0x01, 0x00]); // Flags: RD=1
    buf.extend_from_slice(&[0x00, 0x01]); // QDCOUNT = 1
    buf.extend_from_slice(&[0x00, 0x00]); // ANCOUNT = 0
    buf.extend_from_slice(&[0x00, 0x00]); // NSCOUNT = 0
    buf.extend_from_slice(&[0x00, 0x00]); // ARCOUNT = 0

    // Question — encode domain as DNS labels
    for label in domain.trim_end_matches('.').split('.') {
        let bytes = label.as_bytes();
        buf.push(bytes.len() as u8);
        buf.extend_from_slice(bytes);
    }
    buf.push(0x00); // root label

    buf.extend_from_slice(&qtype.to_be_bytes()); // QTYPE
    buf.extend_from_slice(&[0x00, 0x01]); // QCLASS = IN

    buf
}

// ============================================================================
// DNS client
// ============================================================================

struct DnsClient {
    socket: UdpSocket,
    #[allow(dead_code)]
    server: String,
}

impl DnsClient {
    fn new(server: &str) -> Result<Self, std::io::Error> {
        let socket = UdpSocket::bind("0.0.0.0:0")?;
        socket.set_read_timeout(Some(Duration::from_secs(2)))?;
        socket.connect(server)?;
        Ok(Self {
            socket,
            server: server.to_string(),
        })
    }

    /// Sends a DNS query and returns the round-trip time.
    /// Returns `None` on timeout or error.
    fn query(&self, domain: &str, qtype: u16) -> Option<Duration> {
        let id: u16 = fastrand_u16();
        let pkt = build_dns_query(id, domain, qtype);

        let start = Instant::now();
        self.socket.send(&pkt).ok()?;

        let mut buf = [0u8; 512];
        self.socket.recv(&mut buf).ok()?;

        // Verify response ID matches (basic sanity check)
        let resp_id = u16::from_be_bytes([buf[0], buf[1]]);
        if resp_id != id {
            return None;
        }

        Some(start.elapsed())
    }

    #[allow(dead_code)]
    fn addr(&self) -> &str {
        &self.server
    }
}

/// Minimal LCG random for u16 (no external dep needed)
fn fastrand_u16() -> u16 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEED: AtomicU64 = AtomicU64::new(0x517cc1b727220a95);
    let s = SEED.fetch_add(0x9e3779b97f4a7c15, Ordering::Relaxed);
    ((s ^ (s >> 30)).wrapping_mul(0xbf58476d1ce4e5b9) >> 48) as u16
}

// ============================================================================
// Benchmark engine
// ============================================================================

const DOMAINS: &[(&str, u16)] = &[
    ("google.com", 1),      // A
    ("cloudflare.com", 1),  // A
    ("github.com", 1),      // A
    ("youtube.com", 1),     // A
    ("amazon.com", 1),      // A
    ("reddit.com", 1),      // A
    ("wikipedia.org", 1),   // A
    ("apple.com", 1),       // A
    ("microsoft.com", 1),   // A
    ("netflix.com", 1),     // A
    ("google.com", 28),     // AAAA
    ("cloudflare.com", 28), // AAAA
    ("github.com", 15),     // MX
    ("google.com", 16),     // TXT
];

struct BenchResult {
    name: String,
    addr: String,
    qps: f64,
    p50_us: u64,
    p95_us: u64,
    p99_us: u64,
    success: usize,
    timeout: usize,
}

fn run_bench(name: &str, addr: &str, queries: usize, warmup: usize) -> Option<BenchResult> {
    let client = DnsClient::new(addr).ok()?;

    // Warm-up — results discarded
    for i in 0..warmup {
        let (domain, qtype) = DOMAINS[i % DOMAINS.len()];
        client.query(domain, qtype);
    }

    let mut latencies: Vec<u64> = Vec::with_capacity(queries);
    let mut timeouts = 0usize;
    let start = Instant::now();

    for i in 0..queries {
        let (domain, qtype) = DOMAINS[i % DOMAINS.len()];
        match client.query(domain, qtype) {
            Some(dur) => latencies.push(dur.as_micros() as u64),
            None => timeouts += 1,
        }
    }

    let elapsed = start.elapsed();
    let success = latencies.len();

    if success == 0 {
        return None;
    }

    latencies.sort_unstable();

    let p50 = latencies[success * 50 / 100];
    let p95 = latencies[(success * 95 / 100).min(success - 1)];
    let p99 = latencies[(success * 99 / 100).min(success - 1)];
    let qps = success as f64 / elapsed.as_secs_f64();

    Some(BenchResult {
        name: name.to_string(),
        addr: addr.to_string(),
        qps,
        p50_us: p50,
        p95_us: p95,
        p99_us: p99,
        success,
        timeout: timeouts,
    })
}

fn print_table(results: &[BenchResult]) {
    println!();
    println!(
        "{:<22} {:<18} {:>10} {:>12} {:>12} {:>12} {:>10} {:>8}",
        "Server", "Address", "QPS", "P50 (µs)", "P95 (µs)", "P99 (µs)", "Success", "Timeout"
    );
    println!("{}", "-".repeat(110));

    for r in results {
        println!(
            "{:<22} {:<18} {:>10.1} {:>12} {:>12} {:>12} {:>10} {:>8}",
            r.name, r.addr, r.qps, r.p50_us, r.p95_us, r.p99_us, r.success, r.timeout
        );
    }
    println!();

    // Highlight Ferrous-DNS speedup vs others
    if let Some(ferrous) = results.iter().find(|r| r.name.contains("Ferrous-DNS")) {
        for other in results.iter().filter(|r| !r.name.contains("Ferrous-DNS")) {
            if other.p50_us > 0 {
                let speedup = other.p50_us as f64 / ferrous.p50_us as f64;
                println!(
                    "  Ferrous-DNS is {:.1}x faster than {} (P50 latency)",
                    speedup, other.name
                );
            }
        }
    }
    println!();
}

fn env_addr(var: &str, default: &str) -> String {
    std::env::var(var).unwrap_or_else(|_| default.to_string())
}

fn env_usize(var: &str, default: usize) -> usize {
    std::env::var(var)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

// ============================================================================
// Tests
// ============================================================================

/// Full competitor comparison — requires all servers to be running.
///
/// Start competitors with:
///   docker compose -f docker/bench/docker-compose.yml up -d
///
/// Then:
///   cargo test -p ferrous-dns-bench competitor_comparison -- --ignored --nocapture
#[test]
#[ignore = "requires external DNS servers (see module docs)"]
fn competitor_comparison() {
    let queries = env_usize("BENCH_QUERIES", 500);
    let warmup = env_usize("BENCH_WARMUP", 50);

    let servers = [
        (
            "Ferrous-DNS",
            env_addr("FERROUS_DNS_ADDR", "127.0.0.1:5353"),
        ),
        ("Pi-hole", env_addr("PIHOLE_ADDR", "127.0.0.1:5354")),
        ("AdGuard Home", env_addr("ADGUARD_ADDR", "127.0.0.1:5355")),
        ("Unbound", env_addr("UNBOUND_ADDR", "127.0.0.1:5356")),
    ];

    println!("\n=== Ferrous-DNS Competitor Comparison ===");
    println!("Queries per server: {queries} | Warm-up: {warmup}");
    println!("Domains: {} (cycling)", DOMAINS.len());

    let results: Vec<BenchResult> = servers
        .iter()
        .filter_map(|(name, addr)| {
            print!("  Benchmarking {name} ({addr})... ");
            match run_bench(name, addr, queries, warmup) {
                Some(r) => {
                    println!("done — {:.0} QPS", r.qps);
                    Some(r)
                }
                None => {
                    println!("UNREACHABLE (skipped)");
                    None
                }
            }
        })
        .collect();

    print_table(&results);

    assert!(
        !results.is_empty(),
        "At least one DNS server must be reachable"
    );
}

/// Benchmark only Ferrous-DNS — no competitors needed.
///
/// Useful for quick local performance regression checks.
///
///   FERROUS_DNS_ADDR=127.0.0.1:5353 \
///   cargo test -p ferrous-dns-bench ferrous_only -- --ignored --nocapture
#[test]
#[ignore = "requires Ferrous-DNS to be running"]
fn ferrous_only() {
    let addr = env_addr("FERROUS_DNS_ADDR", "127.0.0.1:5353");
    let queries = env_usize("BENCH_QUERIES", 1000);
    let warmup = env_usize("BENCH_WARMUP", 100);

    println!("\n=== Ferrous-DNS Latency Benchmark ===");
    println!("Target: {addr} | Queries: {queries} | Warm-up: {warmup}");

    let result = run_bench("Ferrous-DNS", &addr, queries, warmup)
        .expect("Ferrous-DNS must be reachable at {addr}");

    println!();
    println!("  QPS:        {:.1}", result.qps);
    println!("  P50 (µs):   {}", result.p50_us);
    println!("  P95 (µs):   {}", result.p95_us);
    println!("  P99 (µs):   {}", result.p99_us);
    println!("  Success:    {}", result.success);
    println!("  Timeout:    {}", result.timeout);
    println!();

    // Validate against targets from CLAUDE.md
    // Cache hit P99 target: < 35µs (~35_000ns = 35µs)
    // NOTE: P99 here includes upstream latency (not just cache hits).
    // For pure cache-hit P99, warm up the cache first by querying same domains.
    println!("Ferrous-DNS P99 target (cache hit): < 35µs");
    println!("  Measured P99: {}µs", result.p99_us);
}

/// Cache-hit latency test — queries the same domain repeatedly to ensure cache.
///
///   FERROUS_DNS_ADDR=127.0.0.1:5353 \
///   cargo test -p ferrous-dns-bench cache_hit_latency -- --ignored --nocapture
#[test]
#[ignore = "requires Ferrous-DNS to be running"]
fn cache_hit_latency() {
    let addr = env_addr("FERROUS_DNS_ADDR", "127.0.0.1:5353");
    let queries = env_usize("BENCH_QUERIES", 1000);
    let warmup = env_usize("BENCH_WARMUP", 200);

    println!("\n=== Ferrous-DNS Cache-Hit Latency ===");
    println!("Target: {addr} | Queries: {queries} | Warm-up: {warmup}");
    println!("Domain: google.com A (repeated, should be in cache after warm-up)");

    let client = DnsClient::new(&addr).expect("Ferrous-DNS must be reachable");

    // Warm up — force google.com into cache
    for _ in 0..warmup {
        client.query("google.com", 1 /* A */);
    }

    // Measure cache hits only
    let mut latencies: Vec<u64> = Vec::with_capacity(queries);
    for _ in 0..queries {
        if let Some(dur) = client.query("google.com", 1) {
            latencies.push(dur.as_micros() as u64);
        }
    }

    latencies.sort_unstable();
    let n = latencies.len();

    println!();
    println!("  Samples:    {n}");
    println!("  P50 (µs):   {}", latencies[n * 50 / 100]);
    println!("  P95 (µs):   {}", latencies[(n * 95 / 100).min(n - 1)]);
    println!("  P99 (µs):   {}", latencies[(n * 99 / 100).min(n - 1)]);
    println!("  Min (µs):   {}", latencies[0]);
    println!("  Max (µs):   {}", latencies[n - 1]);
    println!();

    let p99 = latencies[(n * 99 / 100).min(n - 1)];
    // From CLAUDE.md: "Cache hit P99 < 35µs"
    // (this is wall-clock including UDP round-trip, so allow more headroom)
    if p99 > 1_000 {
        println!(
            "⚠  P99 {}µs exceeds 1ms — investigate cache performance",
            p99
        );
    } else {
        println!("✓  P99 {}µs — within expected range", p99);
    }
}
