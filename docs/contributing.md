# Contributing

Contributions are welcome — bug reports, feature requests, documentation improvements, and pull requests.

---

## Quick Start

### 1. Fork & Clone

```bash
git clone https://github.com/YOUR_USERNAME/Ferrous-DNS.git
cd Ferrous-DNS

# Add upstream
git remote add upstream https://github.com/ferrous-networking/Ferrous-DNS.git
```

### 2. Create a Branch

```bash
git fetch upstream
git checkout main
git merge upstream/main
git checkout -b feature/your-feature-name
```

**Branch naming**:

| Prefix | Use for |
|:-------|:--------|
| `feature/` | New features |
| `fix/` | Bug fixes |
| `docs/` | Documentation |
| `refactor/` | Code refactoring |
| `perf/` | Performance improvements |
| `test/` | Tests |

### 3. Make Changes

```bash
# Format
cargo fmt --all

# Lint (must pass with zero warnings)
cargo clippy --all-targets --workspace -- -D warnings

# Test
cargo test --workspace
```

### 4. Commit

Use [Conventional Commits](https://www.conventionalcommits.org/):

```bash
git commit -m "feat(cache): add LFU-K eviction policy

- Implement sliding window frequency scoring
- Track K most recent access timestamps
- Add configuration options to ferrous-dns.toml

Closes #123"
```

**Types**: `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`, `chore`

**Valid scopes**: `cache`, `dns`, `api`, `api-pihole`, `infrastructure`, `jobs`, `cli`, `hot-path`, `blocking`, `resolver`

### 5. Push & PR

```bash
git push origin feature/your-feature-name
```

Open a Pull Request on GitHub.

---

## Pull Request Checklist

- [ ] `cargo fmt --all` — code formatted
- [ ] `cargo clippy --all-targets --workspace -- -D warnings` — zero warnings
- [ ] `cargo test --workspace` — all tests pass
- [ ] Tests added for new features
- [ ] No `unwrap()` or `expect()` outside tests and one-time initialization
- [ ] No `panic!` in production code
- [ ] Conventional commit message
- [ ] Synced with `upstream/main`

---

## Code Standards

### Error Handling

```rust
// Always return Result — never panic in production code
pub fn parse_domain(input: &str) -> Result<Domain, DomainError> {
    if input.is_empty() {
        return Err(DomainError::InvalidInput("empty domain".into()));
    }
    Ok(Domain::new(input))
}
```

### Naming

```rust
// Descriptive, not abbreviated
pub fn resolve_dns_query() {}
const MAX_CACHE_ENTRIES: usize = 200_000;

// Not:
pub fn rslv() {}
const MCE: usize = 200000;
```

### Comments

Only comment what the code cannot express:

```rust
// Required: safety justification for unsafe blocks
// SAFETY: `_rdtsc` is available on all x86_64 CPUs.
unsafe { core::arch::x86_64::_rdtsc() }

// Required: non-obvious performance invariant
// Bloom check before regex: avoids O(n) pattern matching on 99% cache hits.
if self.bloom.check(domain) && self.matches_regex(domain) { ... }

// Required: doc comments on public API items
/// Resolves a DNS query, checking L1/L2 cache before forwarding upstream.
pub async fn resolve(&self, query: &DnsQuery) -> Result<DnsResolution, DomainError> { ... }

// Forbidden: comments that explain "what" (the code should be self-explanatory)
let ttl = record.ttl; // gets the TTL ← never write this
```

---

## Architecture Rules

Before making changes, read the [Architecture Overview](architecture/overview.md). The key rules:

1. **`domain` has zero external dependencies** — no I/O, no frameworks, no DB
2. **`application` never imports `infrastructure`** — only traits (ports)
3. **`api` and `api-pihole` never import each other** — only `cli` knows both
4. **Use cases receive `Arc<dyn Port>`** — never instantiate concrete types in use cases
5. **`cli/wiring/` is the only place** where concrete types are wired together

### Adding a New Feature (Checklist)

For a complete feature (e.g. "DNS Tunneling Detection"):

```text
1. domain/        → entity or value object if needed
2. application/   → port trait + use case
3. infrastructure/ → concrete implementation
4. api/           → handler + DTO (if REST endpoint needed)
5. jobs/          → job (if periodic processing needed)
6. cli/wiring/    → inject into dependency graph
7. migrations/    → SQL migration (if DB schema changes)
8. tests/         → mock + integration tests
```

---

## Testing

### Structure

```rust
// Test names describe expected behavior, not implementation
#[test]
fn cache_hit_returns_cached_record_without_upstream_call() { ... }

#[tokio::test]
async fn create_blocklist_source_fails_when_name_already_exists() { ... }
```

### Mocks

Mocks implement the same trait as production code:

```rust
pub struct MockDnsResolver {
    responses: Arc<RwLock<HashMap<String, DnsResolution>>>,
}

impl DnsResolver for MockDnsResolver {
    async fn resolve(&self, query: &DnsQuery) -> Result<DnsResolution, DomainError> {
        // test implementation
    }
}
```

### Coverage Targets

| Crate | Minimum |
|:------|:--------|
| domain | 90% |
| application | 85% |
| infrastructure | 70% |
| api | 75% |
| global | 80% |

```bash
cargo tarpaulin --workspace --out Html
```

---

## Development Commands

```bash
# Build (optimized for your CPU)
RUSTFLAGS="-C target-cpu=native" cargo build --release

# Tests with logging
RUST_LOG=debug cargo test --workspace

# Code coverage
cargo install cargo-tarpaulin
cargo tarpaulin --workspace --out Html

# Format
cargo fmt --all

# Lint (strict)
cargo clippy --all-targets --all-features --workspace -- -D warnings

# Check inter-crate dependencies
cargo tree --workspace

# Run benchmarks
cargo bench -p ferrous-dns-infrastructure
```

---

## Getting Help

- **Issues**: [GitHub Issues](https://github.com/ferrous-networking/Ferrous-DNS/issues)
- **Discussions**: [GitHub Discussions](https://github.com/ferrous-networking/Ferrous-DNS/discussions)
