# Contributing to Ferrous DNS

Thanks for your interest in contributing! 🎉

---

## 🚀 Quick Start

### 1. Fork & Clone

```bash
# Fork the repo on GitHub, then:
git clone https://github.com/YOUR_USERNAME/ferrous-dns.git
cd ferrous-dns

# Add upstream
git remote add upstream https://github.com/andersonviudes/ferrous-dns.git
```

### 2. Create Branch

```bash
# Sync with main
git fetch upstream
git checkout main
git merge upstream/main

# Create feature branch
git checkout -b feature/your-feature-name
```

**Branch naming:**

- `feature/` - New features
- `fix/` - Bug fixes
- `docs/` - Documentation
- `refactor/` - Code refactoring
- `test/` - Tests

### 3. Make Changes

```bash
# Code...

# Format
cargo fmt

# Lint
cargo clippy -- -D warnings

# Test
cargo test
```

### 4. Commit

Use [Conventional Commits](https://www.conventionalcommits.org/):

```bash
git commit -m "feat: add DNS caching

- Implement LRU cache
- Add TTL support
- Include tests

Closes #123"
```

**Types:** `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`, `chore`

### 5. Push & PR

```bash
git push origin feature/your-feature-name
```

Then create a Pull Request on GitHub.

---

## 📝 Commit Messages

### Format

```
<type>: <description>

[optional body]

[optional footer]
```

### Examples

```bash
# Simple
git commit -m "feat: add blocklist import"

# With scope
git commit -m "fix(dns): resolve memory leak"

# With body
git commit -m "feat(api): add pagination

- Add limit and offset parameters
- Update API docs
- Include tests"

# Breaking change
git commit -m "feat!: change API response format

BREAKING CHANGE: timestamps now ISO 8601"
```

---

## 🔍 Pull Request

### Checklist

- [ ] `cargo fmt` - Code formatted
- [ ] `cargo clippy` - No warnings
- [ ] `cargo test` - All tests pass
- [ ] Tests added for new features
- [ ] Documentation updated
- [ ] Conventional commits
- [ ] Synced with upstream/main

### Template

```markdown
## What

Brief description of changes.

## Why

Why this change is needed.

## How

Technical implementation details.

## Testing

How you tested this.

Closes #123
```

---

## 💬 Code Review

### For Contributors

**Receiving feedback:**

- Be open - reviews improve code quality
- Ask questions if unclear
- Respond promptly
- Thank reviewers

**Good responses:**

```
✅ "Good catch! Fixed in commit abc123"
✅ "I chose X because Y, but happy to discuss alternatives"

❌ "Done"
❌ [No response]
```

### For Reviewers

**Be constructive:**

```
✅ "Consider HashSet for O(1) lookups. Large blocklists 
   would benefit from better performance."

❌ "This is slow."
```

**Explain why:**

```
✅ "Validate domain here - malformed input could panic 
   in the DNS parser (line 45)."

❌ "Add validation."
```

**Mark severity:**

```
❗ Required: "This panics if vector is empty - must fix"
💡 Optional: "Nit: extract helper function for readability"
```

---

## ✅ Code Standards

### Formatting

```rust
// ✅ Good
pub struct DnsRecord {
    domain: DomainName,
    ttl: u32,
}

// ❌ Bad
pub struct DnsRecord {
    domain: DomainName,
    ttl: u32
}
```

### Naming

```rust
// ✅ Good
pub fn resolve_dns_query() {}
const MAX_CACHE_SIZE: usize = 10_000;

// ❌ Bad
pub fn rslv() {}
const MCS: usize = 10000;
```

### Error Handling

```rust
// ✅ Good
pub fn parse(input: &str) -> Result<Domain, Error> {
    if input.is_empty() {
        return Err(Error::Empty);
    }
    Ok(Domain::new(input))
}

// ❌ Bad
pub fn parse(input: &str) -> Domain {
    if input.is_empty() {
        panic!("Empty!");  // Don't panic!
    }
    Domain::new(input)
}
```

### Documentation

```rust
/// Resolves DNS query.
///
/// # Arguments
/// * `domain` - Domain to resolve
///
/// # Returns
/// `Ok(Record)` on success, `Err` on failure
///
/// # Example
/// ```
/// let record = resolve("example.com")?;
/// ```
pub async fn resolve(&self, domain: &str) -> Result<Record> {
    // ...
}
```

### Testing

```rust
#[test]
fn test_valid_domain_accepted() {
    let result = Domain::new("example.com");
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_resolver_queries_upstream() {
    let resolver = Resolver::new();
    let record = resolver.resolve("example.com").await;
    assert!(record.is_ok());
}
```

---

## 🏗️ Architecture

Follow **Clean Architecture**:

**Domain** (`crates/domain`)

- ✅ Pure business logic
- ✅ Zero external deps (except `thiserror`)
- ❌ No I/O, no frameworks

**Application** (`crates/application`)

- ✅ Use cases
- ✅ Ports (traits)
- ❌ No infrastructure details

**Infrastructure** (`crates/infrastructure`)

- ✅ Database, cache, DNS adapters
- ✅ Implements application ports

---

## 🧪 Testing

```bash
# Run all tests
cargo test

# Run specific crate
cargo test -p ferrous-dns-domain

# With logging
RUST_LOG=debug cargo test

# Coverage
cargo install cargo-tarpaulin
cargo tarpaulin --out Html
```

**Coverage targets:**

- Domain: >90%
- Application: >85%
- Infrastructure: >70%
- Overall: >80%

---

## 🤝 Community

- **Issues** - Bug reports, feature requests
- **Discussions** - Questions, ideas
- **Discord** - Coming soon

---

## 🎉 Thank You!

Every contribution matters! Happy coding! 🦀
