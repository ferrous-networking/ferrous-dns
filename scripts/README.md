# 📜 Ferrous DNS - Scripts

Automation scripts for release management and development tasks.

## 📋 Available Scripts

### `release.sh`

Automated release script that handles the complete release process.

**Usage:**
```bash
./scripts/release.sh [major|minor|patch]
```

**What it does:**
1. ✅ Validates git status (clean working directory)
2. ✅ Runs test suite
3. ✅ Runs code quality checks (fmt, clippy)
4. ✅ Bumps version in all Cargo.toml files
5. ✅ Updates CHANGELOG.md (if git-cliff is installed)
6. ✅ Creates git commit
7. ✅ Creates git tag
8. ✅ Pushes to remote

**Examples:**
```bash
# Patch release: 0.1.0 -> 0.1.1
./scripts/release.sh patch

# Minor release: 0.1.0 -> 0.2.0
./scripts/release.sh minor

# Major release: 0.1.0 -> 1.0.0
./scripts/release.sh major
```

---

### `bump-version.sh`

Updates version numbers in all workspace Cargo.toml files.

**Usage:**
```bash
./scripts/bump-version.sh [major|minor|patch|VERSION]
```

**What it does:**
1. ✅ Gets current version from workspace Cargo.toml
2. ✅ Calculates new version
3. ✅ Updates version in all crate Cargo.toml files
4. ✅ Validates version format

**Examples:**
```bash
# Bump patch version
./scripts/bump-version.sh patch

# Bump minor version
./scripts/bump-version.sh minor

# Set specific version
./scripts/bump-version.sh 1.2.3
```

---

## 🛠️ Prerequisites

### Required Tools

- **bash** - Shell interpreter
- **cargo** - Rust package manager
- **git** - Version control
- **jq** - JSON processor

### Optional Tools (Recommended)

- **cargo-release** - Automated release management
  ```bash
  cargo install cargo-release
  ```

- **git-cliff** - Changelog generator
  ```bash
  cargo install git-cliff
  ```

---

## 🚀 Quick Start

### First Time Setup

```bash
# Make scripts executable
chmod +x scripts/*.sh

# Install optional tools
make install-tools
```

### Creating a Release

```bash
# 1. Make sure you're on main branch
git checkout main
git pull

# 2. Run release script
./scripts/release.sh patch

# 3. Done! GitHub Actions will handle the rest
```

---

## 🔄 Release Workflow

### Automatic (Recommended)

```bash
# Run release script - it handles everything
./scripts/release.sh patch
```

### Manual (Step by Step)

```bash
# 1. Run tests
cargo test --all-features --workspace

# 2. Run checks
cargo fmt -- --check
cargo clippy -- -D warnings

# 3. Bump version
./scripts/bump-version.sh patch

# 4. Update changelog
git-cliff --tag v0.1.1 --output CHANGELOG.md

# 5. Commit and tag
git commit -am "chore: release v0.1.1"
git tag -a v0.1.1 -m "Release v0.1.1"

# 6. Push
git push origin main
git push origin v0.1.1
```

---

## 📝 Semantic Versioning

Ferrous DNS follows [Semantic Versioning](https://semver.org/):

- **MAJOR** (1.0.0) - Breaking changes
- **MINOR** (0.1.0) - New features, backward compatible
- **PATCH** (0.0.1) - Bug fixes, backward compatible

### When to Use Each

**Patch (0.0.X)**
- Bug fixes
- Performance improvements
- Documentation updates
- Internal refactoring

**Minor (0.X.0)**
- New features
- New APIs
- Deprecations (with backward compatibility)

**Major (X.0.0)**
- Breaking API changes
- Removed deprecated features
- Major architectural changes

---

## 🎯 Conventional Commits

Scripts rely on [Conventional Commits](https://www.conventionalcommits.org/) for changelog generation.

### Commit Format

```
<type>(<scope>): <description>

[optional body]

[optional footer]
```

### Types

- `feat:` - New feature
- `fix:` - Bug fix
- `docs:` - Documentation changes
- `style:` - Code style changes (formatting)
- `refactor:` - Code refactoring
- `perf:` - Performance improvements
- `test:` - Adding or updating tests
- `chore:` - Maintenance tasks
- `ci:` - CI/CD changes
- `build:` - Build system changes

### Examples

```bash
# New feature
git commit -m "feat: add DNS-over-HTTPS support"

# Bug fix
git commit -m "fix: resolve memory leak in cache"

# Breaking change
git commit -m "feat!: change API response format

BREAKING CHANGE: Response format changed from XML to JSON"
```

---

## 🐛 Troubleshooting

### Scripts Not Executable

```bash
chmod +x scripts/*.sh
```

### Git Not Clean

```bash
# Check status
git status

# Stash changes
git stash

# Or commit changes
git add .
git commit -m "fix: some changes"
```

### Version Mismatch

```bash
# Check current version
grep '^version = ' Cargo.toml

# Manually fix version
./scripts/bump-version.sh 0.1.0
```

### jq Not Found

```bash
# Ubuntu/Debian
sudo apt-get install jq

# macOS
brew install jq

# Arch Linux
sudo pacman -S jq
```

### cargo-release Not Working

```bash
# Install cargo-release
cargo install cargo-release

# Or use our scripts instead
./scripts/release.sh patch
```

---

## 📚 Additional Resources

- [Semantic Versioning](https://semver.org/)
- [Conventional Commits](https://www.conventionalcommits.org/)
- [git-cliff Documentation](https://git-cliff.org/)
- [cargo-release Documentation](https://github.com/crate-ci/cargo-release)

---

## 📄 License

MIT OR Apache-2.0
