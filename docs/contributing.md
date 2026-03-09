# Contributing

Contributions are welcome — bug reports, feature requests, documentation improvements, and pull requests.

---

## Quick Start

### 1. Fork & Clone

```bash
git clone https://github.com/YOUR_USERNAME/ferrous-dns.git
cd ferrous-dns

# Add upstream
git remote add upstream https://github.com/ferrous-networking/ferrous-dns.git
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

- Always return `Result` -- never panic in production code
- Use `DomainError` for all domain-level errors
- Propagate errors with `?` -- don't swallow them silently

### Naming

- Use descriptive names, not abbreviations (e.g., `resolve_dns_query()` not `rslv()`)
- Constants should be clear: `MAX_CACHE_ENTRIES` not `MCE`

### Comments

Only comment what the code cannot express:

- **Required**: safety justification for `unsafe` blocks
- **Required**: non-obvious performance invariants
- **Required**: doc comments on public API items
- **Forbidden**: comments that explain "what" -- the code should be self-explanatory

---

## Architecture Rules

Before making changes, read the [Architecture Overview](architecture/overview.md). The key rules:

1. **Domain layer has zero external dependencies** -- no I/O, no frameworks, no DB
2. **Application layer never imports infrastructure** -- only abstract interfaces (ports)
3. **API layers never import each other** -- only the CLI entrypoint knows both
4. **Use cases receive abstract interfaces** -- never instantiate concrete types in use cases
5. **Wiring is centralized** -- concrete types are only assembled in one place

### Adding a New Feature (Checklist)

For a complete feature (e.g. "DNS Tunneling Detection"):

1. **Domain layer** -- entity or value object if needed
2. **Application layer** -- port trait + use case
3. **Infrastructure layer** -- concrete implementation
4. **API layer** -- handler + DTO (if REST endpoint needed)
5. **Jobs** -- background job (if periodic processing needed)
6. **Wiring** -- inject into dependency graph
7. **Migrations** -- SQL migration (if DB schema changes)
8. **Tests** -- mock + integration tests

---

## Testing

### Structure

Test names should describe expected behavior, not implementation details. Examples:

- `cache_hit_returns_cached_record_without_upstream_call`
- `create_blocklist_source_fails_when_name_already_exists`

### Mocks

Mocks implement the same interface as production code. This ensures that any implementation can be swapped in tests without changing the calling code.

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
cargo bench --workspace
```

---

## Getting Help

- **Issues**: [GitHub Issues](https://github.com/ferrous-networking/ferrous-dns/issues)
- **Discussions**: [GitHub Discussions](https://github.com/ferrous-networking/ferrous-dns/discussions)
