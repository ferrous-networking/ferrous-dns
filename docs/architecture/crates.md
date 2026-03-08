# Crate Structure

Ferrous DNS is organized as a Rust workspace with 7 crates. Each crate has a single, well-defined responsibility.

---

## Workspace Layout

```text
ferrous-dns/
├── crates/
│   ├── domain/          # Entities, value objects, domain errors — zero external deps
│   ├── application/     # Use cases, ports (traits), orchestration services
│   ├── infrastructure/  # DB, cache, DNS adapters, resolvers, transport
│   ├── api/             # HTTP handlers, DTOs, REST routes, middleware
│   ├── api-pihole/      # Pi-hole v6 API adapter
│   ├── jobs/            # Background jobs, scheduler, job runner
│   └── cli/             # Entrypoint, dependency wiring, server bootstrap
├── tests/               # Integration tests (cross-crate)
│   ├── common/          # Shared test helpers
│   ├── flows/           # End-to-end flow tests
│   └── performance/     # Benchmarks
├── web/static/          # Frontend (HTMX + Alpine.js + TailwindCSS)
├── migrations/          # SQLite migrations (sqlx)
└── Cargo.toml           # Workspace root
```

---

## `crates/domain`

**Pure business logic. Zero external dependencies** (except `thiserror`).

Contains:
- DNS record entities (`DnsRecord`, `DnsQuery`, `DnsResolution`)
- Value objects (`DomainName`, `RecordType`, `ClientGroup`)
- Domain configuration types
- `DomainError` — the single error type used across all layers
- Business rules that don't depend on any I/O

```rust
// Example entity — no imports from other crates
pub struct DnsRecord {
    pub domain: Arc<str>,
    pub record_type: RecordType,
    pub ttl: u32,
    pub data: RecordData,
}
```

**Rule**: nothing outside of `thiserror` is imported here. If you need I/O, it belongs in `infrastructure`.

---

## `crates/application`

**Use cases and ports. Depends only on `domain`.**

Contains:
- Use cases (one file per operation, e.g. `handle_dns_query.rs`, `create_blocklist_source.rs`)
- Port traits (`DnsResolver`, `BlocklistSourceRepository`, `QueryLogRepository`)
- Orchestration services (subnet matching, schedule evaluation)
- No infrastructure details

```rust
// Port definition — just a trait, no implementation
#[async_trait]
pub trait DnsResolver: Send + Sync {
    fn try_cache(&self, query: &DnsQuery) -> Option<DnsResolution>;
    async fn resolve(&self, query: &DnsQuery) -> Result<DnsResolution, DomainError>;
}

// Use case — receives ports via injection
pub struct HandleDnsQueryUseCase {
    resolver: Arc<dyn DnsResolver>,
    block_filter: Arc<dyn BlockFilterEnginePort>,
    query_log: Arc<dyn QueryLogRepository>,
}
```

**Rule**: use cases never instantiate infrastructure types. They receive `Arc<dyn Port>` via constructor injection.

---

## `crates/infrastructure`

**Implements all ports. Knows about I/O.**

Contains:
- SQLite repositories (`SqliteBlocklistSourceRepository`, `SqliteQueryLogRepository`, etc.)
- DNS resolver pipeline (`CoreResolver`, `CachedResolver`, `DnssecResolver`, `FilteredResolver`)
- DNS transport implementations (`udp.rs`, `tls.rs`, `https.rs`, `quic.rs`, `h3.rs`)
- Upstream load balancer (`Parallel`, `Balanced`, `Failover` strategies)
- Cache L1/L2 (`thread_local.rs`, `dashmap_cache.rs`)
- Bloom filter
- In-flight coalescing map
- `ResolverBuilder` for assembling the resolver pipeline
- Background job implementations

```text
crates/infrastructure/src/
├── repositories/
├── dns/
│   ├── resolver/
│   │   ├── builder.rs      # Builder pattern
│   │   ├── cache_layer.rs  # CachedResolver (Decorator)
│   │   ├── core.rs         # CoreResolver (upstream forwarding)
│   │   └── filters.rs      # FilteredResolver (safe search, query filters)
│   ├── transport/
│   │   ├── udp.rs
│   │   ├── tcp.rs
│   │   ├── tls.rs
│   │   ├── https.rs
│   │   ├── quic.rs
│   │   └── h3.rs
│   └── load_balancer/
│       ├── strategy.rs     # Strategy enum dispatch
│       ├── balanced.rs
│       ├── failover.rs
│       └── parallel.rs
└── cache/
    ├── l1/
    └── l2/
```

---

## `crates/api`

**Axum HTTP handlers for the Ferrous DNS REST API.**

Contains:
- Route handlers (one file per resource, e.g. `blocklist_sources.rs`, `query_log.rs`)
- Request/response DTOs
- `AppState` — shared state injected into all handlers
- `ApiError` — maps `DomainError` to HTTP status codes
- Middleware (API key, compression)

```rust
// Handler delegates to use case — zero business logic in handlers
pub async fn create(
    State(state): State<Arc<AppState>>,
    Json(body): Json<CreateBlocklistSourceRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let input = CreateBlocklistSourceInput::from(body);
    let source = state.use_cases.create_blocklist_source.execute(input).await?;
    Ok((StatusCode::CREATED, Json(BlocklistSourceResponse::from(source))))
}
```

**Rule**: handlers never access infrastructure directly. All data access is through use cases.

---

## `crates/api-pihole`

**Pi-hole v6 API compatibility adapter.**

A thin layer that exposes the Pi-hole v6 REST API format at `/api/*`, reusing the same use cases from `application`. Enables third-party Pi-hole integrations to work with Ferrous DNS without modification.

- Never imports `crates/api`
- Never imports `crates/infrastructure`
- Reuses all use cases from `application`

---

## `crates/jobs`

**Background jobs and scheduler.**

Contains:
- `BlocklistSyncJob` — downloads and indexes blocklists periodically
- `CacheMaintenanceJob` — compaction, expiry cleanup, WAL checkpoint
- `ClientSyncJob` — resolves client hostnames, updates last-seen
- `ScheduleEvaluatorJob` — activates/deactivates time-based blocking rules
- `JobRunner` — assembles and starts all jobs with `CancellationToken` for graceful shutdown

```rust
pub trait SpawnableJob: Send + 'static {
    fn with_cancellation(self, token: CancellationToken) -> Self;
    fn start_job(self: Arc<Self>) -> tokio::task::JoinHandle<()>;
}
```

**Rule**: jobs use ports from `application` only. They never import `infrastructure` directly.

---

## `crates/cli`

**The entrypoint. The only crate that wires everything together.**

Contains:
- `main.rs` — startup, config loading, signal handling
- `wiring/` — dependency injection graph (instantiates concrete types and injects them)
- Server bootstrap (UDP server, TCP server, DoT, DoH, Axum)
- Graceful shutdown coordination

```text
cli/src/
├── main.rs
└── wiring/
    ├── dns/
    │   ├── resolver.rs     # assembles resolver pipeline
    │   ├── pools.rs        # creates upstream pool manager
    │   └── cache.rs        # creates L1/L2 cache
    ├── api.rs              # wires API handlers with use cases
    └── jobs.rs             # wires jobs with repositories
```

**Rule**: `cli` is the only place where concrete infrastructure types (`SqliteBlocklistSourceRepository`, `DashMapCache`, etc.) are instantiated and injected into use cases.

---

## `tests/`

Cross-crate integration tests that test complete flows end-to-end:

```text
tests/
├── common/          # Mock repositories, test builders, helpers
├── flows/           # End-to-end scenarios (block query, cache hit, etc.)
└── performance/     # dnsperf benchmark scripts and data
```

Run all tests:
```bash
cargo test --workspace
```

Run specific crate:
```bash
cargo test -p ferrous-dns-domain
cargo test -p ferrous-dns-application
```

Run with logging:
```bash
RUST_LOG=debug cargo test --workspace
```

---

## Coverage Targets

See [Contributing — Coverage Targets](../contributing.md#coverage-targets) for per-crate minimums and how to run coverage reports.
