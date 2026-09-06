# Contributing to Ferrous DNS

Thanks for your interest in contributing! 🎉

Ferrous DNS is a security-focused, DNSSEC-validating DNS resolver and content
filter. It resolves real traffic for real people, so the bar for correctness is
high — but the workflow below is short, and CI tells you exactly what it wants.

---

## Getting set up

```bash
# Fork the repo on GitHub, then:
git clone https://github.com/YOUR_USERNAME/ferrous-dns.git
cd ferrous-dns

# Add the upstream remote
git remote add upstream https://github.com/ferrous-networking/ferrous-dns.git

# Build and run the test suite once to confirm the toolchain is happy
make build-dev
make test
```

To run the server locally, point it at the config in the repo root:

```bash
cargo run --release --bin ferrous-dns -- --config ferrous-dns.toml
```

If it refuses to start, check the ports (53 needs privileges), the config path,
and file permissions before anything else.

---

## The local gate

**`make ci` is the gate.** It runs exactly what CI runs — formatting check,
clippy with `-D warnings`, and the full test suite:

```bash
make ci          # fmt-check + clippy -D warnings + test — run before every commit
make pre-commit  # same, but formats in place instead of only checking
```

Other targets worth knowing (`make help` lists them all):

| Command | What it does |
|:--|:--|
| `make build` / `make build-dev` | Release / debug build |
| `make test` | Full workspace test suite |
| `make audit` | `cargo audit` — run this before adding or bumping a dependency |
| `make bench` | Criterion benchmarks |
| `make doc` | `cargo doc` for the workspace |
| `make fuzz-short` | Every fuzz target, 60 seconds each |

Coverage has no Make target; use `cargo tarpaulin --workspace --out Html`.

If you use an AI coding agent in this repo, `.claudin/skills/` carries `/verify`
and `/pre-pr`, which mirror the same checks (`/pre-pr` adds `cargo audit` and the
docs version check). They are a convenience, not a substitute — `make ci` is
still what CI runs.

---

## Branches and commits

Create a branch from an up-to-date `main` — never commit to `main` directly:

```bash
git fetch upstream
git checkout main
git merge upstream/main
git checkout -b fix/cache-key-truncation
```

**Branch prefixes:** `feat/`, `fix/`, `docs/`, `refactor/`, `perf/`, `test/`,
`chore/` — the same words as the commit types, not `feature/`.

Commits follow [Conventional Commits](https://www.conventionalcommits.org/):

```bash
git commit -m "fix(cache): stop corrupting non-ASCII bytes in oversized keys

Truncating the key at a byte offset split multi-byte UTF-8 sequences, so
a cached answer for an IDN domain came back mangled. Truncate on a char
boundary instead.

Closes #123"
```

**Types:** `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`, `chore`,
`ci`, `build`.

---

## Opening a pull request

### The title is validated by CI

`.github/workflows/pr-validation.yml` runs
[`action-semantic-pull-request`](https://github.com/amannn/action-semantic-pull-request)
against the **PR title**, not your commits — a bad title fails the build even
with a spotless branch.

Format is `type(scope): description`, scope optional:

```
fix(cache): stop corrupting non-ASCII bytes in oversized cache keys
feat(query-log): record and display the client protocol on each query
docs: rewrite the contributor guide
```

- Lowercase description, written as a full sentence — not `fix: cache bug`.
- Scope is the subsystem: `dns`, `dnssec`, `cache`, `auth`, `api`, `query-log`,
  `block-filter`, `docker`, `config`. Omit it only for repo-wide changes.
- `build(deps): …` is reserved for Dependabot; `ci: …` is for workflow changes.
- Marking a change breaking demands a CHANGELOG entry, a migration guide, and a
  MAJOR bump — don't do it by accident.
- `size/*` labels are applied automatically. Never set them by hand.

### The body

Fill in [the template](.github/PULL_REQUEST_TEMPLATE/pull_request_template.md):
**Summary**, **Related issues**, **Test plan**, **Known follow-ups / out of scope**.

The Summary leads with the behavior change, not the file list, and splits into
named sub-sections when the change spans several areas. The Test plan carries
evidence — the test count, the test files you added, the command you actually
ran and what it printed — rather than intentions.
[PR #219](https://github.com/ferrous-networking/ferrous-dns/pull/219) is the
worked example.

### Before you push

- [ ] `make ci` green
- [ ] Tests added for new behavior
- [ ] `docs/` and `ferrous-dns.toml` updated if you added a feature or a config key
- [ ] `make audit` clean if you touched dependencies
- [ ] Branch synced with `upstream/main`

---

## Code review

**Receiving feedback:** reviews improve the code, not judge you. Ask when
something is unclear, and say what you changed rather than just "done".

```
✅ "Good catch! Fixed in abc123."
✅ "I chose X because Y, but happy to discuss alternatives."
❌ "Done"
```

**Giving feedback:** be specific, explain why, and cite the line.

```
✅ "Validate the domain here — malformed input panics in the DNS parser (parser.rs:45)."
❌ "Add validation."
```

Mark severity so the author knows what actually blocks the merge:

```
❗ Required: "This panics when the vector is empty."
💡 Optional: "Nit: this would read better as a helper."
```

Classify before you weigh: something that **breaks existing behavior** blocks a
merge, something that merely **changes** it is worth writing down, and a
**pre-existing gap the PR widens** should be named as pre-existing rather than
charged to the author.

---

## Architecture

The workspace follows Clean Architecture, and each crate's `Cargo.toml`
enforces the dependency direction:

```
cli → api / api-pihole / jobs → infrastructure → application → domain
```

- **`domain`** — entities and pure business rules. Zero workspace deps and zero
  `async fn`; no tokio, no sqlx.
- **`application`** — depends on `domain` only. Owns every port trait
  (`src/ports/`) and use case (`src/use_cases/<context>/`).
- **`infrastructure`** — implements the ports: repositories in
  `src/repositories/`, resolver/cache/block-filter in `src/dns/`.
- **`api` / `api-pihole`** — thin handlers over concrete use cases.
- **`cli`** — the only crate that may depend on all others; manual DI in
  `src/wiring/`.

A new capability is a port trait plus a `XxxUseCase` plus an infrastructure
adapter. Everything returns `Result<_, DomainError>`; `anyhow` is allowed in
`cli` only. Details and the naming conventions are in
[`.claudin/rules/architecture.md`](.claudin/rules/architecture.md), with code
and web standards alongside it in the same directory.

---

## Testing

Name tests after the behavior they pin down, not the function they call:

```
cache_hit_returns_cached_record_without_upstream_call
create_blocklist_source_fails_when_name_already_exists
```

Coverage targets: domain 90%, application 85%, api 75%, infrastructure 70%,
overall 80%.

### Fuzzing

Anything that parses bytes off the network is fuzzed. If you touch a wire-format
parser, run the matching target before opening the PR — CI runs all of them for
60 seconds each and the job gates merges.

```bash
rustup toolchain install nightly
cargo install cargo-fuzz --version 0.13.2 --locked

make fuzz TARGET=query_fast_path FUZZ_TIME=300   # one target
make fuzz-short                                  # all targets, 60s each
```

When a target crashes, minimize the input with `cargo +nightly fuzz tmin` and
add it as a named test in `crates/infrastructure/tests/fuzz_regressions.rs`
**before** fixing the bug. See [`fuzz/README.md`](fuzz/README.md) for the target
list and the surfaces it deliberately does not cover.

---

## Documentation

The site is [MkDocs](https://www.mkdocs.org/) — sources in `docs/`, nav in
`mkdocs.yml`. `site/` is a build artifact; never edit it by hand.

Dashboard screenshots live in `docs/assets/<area>/`, captured at a **1920x1080
viewport in the light theme** so the set stays visually consistent. Give every
image descriptive alt text.

---

## Getting help

- **Issues** — [github.com/ferrous-networking/ferrous-dns/issues](https://github.com/ferrous-networking/ferrous-dns/issues)
- **Discussions** — [github.com/ferrous-networking/ferrous-dns/discussions](https://github.com/ferrous-networking/ferrous-dns/discussions)
- **Security** — do not open an issue; see [SECURITY.md](.github/SECURITY.md)

Every contribution matters. Happy coding! 🦀
