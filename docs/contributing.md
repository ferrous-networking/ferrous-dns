# Contributing

Contributions are welcome — bug reports, feature requests, documentation
improvements, and pull requests.

The full workflow lives in
[**CONTRIBUTING.md**](https://github.com/ferrous-networking/ferrous-dns/blob/main/CONTRIBUTING.md)
in the repository root: branch and commit conventions, the PR title format that
CI validates, review etiquette, the architecture rules, and the fuzzing policy.
This page keeps the parts you are most likely to want while reading the docs.

---

## The short version

```bash
# Fork on GitHub, then:
git clone https://github.com/YOUR_USERNAME/ferrous-dns.git
cd ferrous-dns
git remote add upstream https://github.com/ferrous-networking/ferrous-dns.git

# Branch from an up-to-date main — prefixes are feat/ fix/ docs/ refactor/ perf/ test/ chore/
git fetch upstream && git checkout main && git merge upstream/main
git checkout -b fix/your-fix

# The gate: exactly what CI runs
make ci
```

Commits follow [Conventional Commits](https://www.conventionalcommits.org/).
**The pull request title is validated by CI** as `type(scope): description` —
a title like `fix: cache bug` fails the build even with a clean branch. Write it
as a lowercase full sentence, for example
`fix(cache): stop corrupting non-ASCII bytes in oversized cache keys`.

---

## Development Commands

```bash
# The gate — formatting check, clippy -D warnings, full test suite
make ci

# Same, but formats in place instead of only checking
make pre-commit

# Build (optimized for your CPU)
RUSTFLAGS="-C target-cpu=native" cargo build --release

# Run the server against the config in the repo root
cargo run --release --bin ferrous-dns -- --config ferrous-dns.toml

# Tests with logging
RUST_LOG=debug cargo test --workspace

# Code coverage (no Make target)
cargo install cargo-tarpaulin
cargo tarpaulin --workspace --out Html

# Security audit — run before adding or bumping a dependency
make audit

# Fuzz every target for 60 seconds each
make fuzz-short

# Check inter-crate dependencies
cargo tree --workspace

# Benchmarks
make bench
```

`make help` lists every target.

---

## Architecture Rules

Before making changes, read the [Architecture Overview](architecture/overview.md).
The dependency direction is enforced by each crate's `Cargo.toml`:

```
cli → api / api-pihole / jobs → infrastructure → application → domain
```

1. **Domain has zero external dependencies** — no I/O, no frameworks, no DB, and
   no `async fn`
2. **Application never imports infrastructure** — only its own port traits
3. **API layers never import each other** — only the CLI entrypoint knows both
4. **Use cases receive abstract interfaces** — never instantiate concrete types
5. **Wiring is centralized** — concrete types are assembled only in `cli/src/wiring/`

### Adding a New Feature (Checklist)

For a complete feature (e.g. "DNS Tunneling Detection"):

1. **Domain layer** — entity or value object if needed
2. **Application layer** — port trait + use case
3. **Infrastructure layer** — concrete implementation
4. **API layer** — handler + DTO (if a REST endpoint is needed)
5. **Jobs** — background job (if periodic processing is needed)
6. **Wiring** — inject into the dependency graph
7. **Migrations** — SQL migration (if the DB schema changes)
8. **Tests** — mock + integration tests
9. **Docs and config** — update `docs/` and `ferrous-dns.toml`

---

## Testing

Test names should describe expected behavior, not implementation details:

- `cache_hit_returns_cached_record_without_upstream_call`
- `create_blocklist_source_fails_when_name_already_exists`

Mocks implement the same port trait as production code, so any implementation can
be swapped in without changing the calling code.

### Coverage Targets

| Crate | Minimum |
|:------|:--------|
| domain | 90% |
| application | 85% |
| api | 75% |
| infrastructure | 70% |
| global | 80% |

Anything that parses bytes off the network is additionally fuzzed, and the fuzz
job gates merges — see the fuzzing section of
[CONTRIBUTING.md](https://github.com/ferrous-networking/ferrous-dns/blob/main/CONTRIBUTING.md).

---

## Getting Help

- **Issues**: [GitHub Issues](https://github.com/ferrous-networking/ferrous-dns/issues)
- **Discussions**: [GitHub Discussions](https://github.com/ferrous-networking/ferrous-dns/discussions)
- **Security**: do not open an issue — use
  [private vulnerability reporting](https://github.com/ferrous-networking/ferrous-dns/security/advisories/new)
