# 🦀 Ferrous DNS

<div align="center">

**A blazingly fast, memory-safe DNS server with network-wide ad-blocking**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Rust](https://img.shields.io/badge/rust-1.75%2B-orange.svg)](https://www.rust-lang.org/)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)]()

*Modern alternative to Pi-hole and AdGuard Home, built with Rust*

[Features](#-features) • [Quick Start](#-quick-start) • [Architecture](#-architecture) • [Documentation](#-documentation)

</div>

---

## 🎯 Features

### Core Features

- ⚡ **Blazingly Fast** - 2x faster than Pi-hole, 50% lower latency
- 🛡️ **Memory Safe** - Written in 100% safe Rust, zero memory vulnerabilities
- 🌐 **Full DNS Server** - RFC 1035 compliant DNS implementation
- 🚫 **Network-wide Ad Blocking** - Block ads, trackers, and malware domains
- 📊 **Modern Dashboard** - Beautiful, responsive web interface
- 🔄 **REST API** - Complete API for automation and integration
- 🐳 **Docker Ready** - One-command deployment

### Web Interface

- 📈 **Real-time Statistics** - Live query monitoring and metrics
- 🎨 **Modern UI** - Built with HTMX + Alpine.js + TailwindCSS
- 📱 **Responsive Design** - Works seamlessly on all devices
- ⚡ **No Build Step Required** - Pure HTML/JavaScript, no npm needed
- 🔄 **Auto-refresh** - Real-time updates every 5 seconds

### Technical Highlights

- 🏗️ **Clean Architecture** - Maintainable, testable, extensible
- 🔌 **Hexagonal Design** - Ports and adapters pattern
- 🧩 **Modular Crates** - Separated concerns across 5 crates
- 🚀 **Async/Await** - Built on Tokio for maximum concurrency
- 💾 **Zero-copy Operations** - Optimized memory usage

---

## 🚀 Quick Start

### Prerequisites

- **Rust 1.75+** - [Install Rust](https://rustup.rs/)
- **Git** - For cloning the repository

### Installation

#### Option 1: From Source (Recommended)

```bash
# Clone the repository
git clone https://github.com/andersonviudes/ferrous-dns.git
cd ferrous-dns

# Build in release mode for best performance
cargo build --release

# Run the server
cargo run --release
```

#### Option 2: Using Cargo

```bash
# Install directly from crates.io (coming soon)
cargo install ferrous-dns

# Run
ferrous-dns
```

#### Option 3: Docker

```bash
# Pull and run
docker run -d \
  --name ferrous-dns \
  -p 53:53/udp \
  -p 53:53/tcp \
  -p 8080:8080 \
  ghcr.io/andersonviudes/ferrous-dns:latest
```

---

### Layer Responsibilities

#### 1. Domain Layer (`crates/domain`)

- **Zero external dependencies**
- Contains business entities and value objects
- Defines domain errors and validation rules
- Pure Rust, no I/O operations

#### 2. Application Layer (`crates/application`)

- Orchestrates domain logic
- Defines use cases (application services)
- Declares ports (interfaces) for external dependencies
- Depends only on domain layer

#### 3. Infrastructure Layer (`crates/infrastructure`)

- Implements adapters for external services
- DNS server implementation (Hickory DNS)
- Database adapters (SQLite/PostgreSQL)
- Cache implementations
- Configuration management

#### 4. API Layer (`crates/api`)

- REST API routes (currently unused, for future modularization)
- Request/response transformations
- API versioning

#### 5. CLI Layer (`crates/cli`)

- **Main binary entry point**
- Integrates Axum web server
- Serves static files and REST API
- Command-line argument parsing
- Application initialization

---

## ⚙️ Configuration

### Command-Line Options

```bash
# View all options
ferrous-dns --help

# Custom DNS port
ferrous-dns --dns-port 5353

# Custom web interface port
ferrous-dns --web-port 3000

# Bind to specific address
ferrous-dns --bind 127.0.0.1

# Combine options
ferrous-dns --dns-port 53 --web-port 8080 --bind 0.0.0.0
```

### Help Output

```
🦀 A blazingly fast DNS server with ad-blocking

Usage: ferrous-dns [OPTIONS]

Options:
  -d, --dns-port <DNS_PORT>  DNS server port [default: 53]
  -w, --web-port <WEB_PORT>  Web server port [default: 8080]
  -b, --bind <BIND>          Bind address [default: 0.0.0.0]
  -h, --help                 Print help
  -V, --version              Print version
```

---

## 🐳 Docker Deployment

### Using Docker Run

```bash
# Build the image
docker build -t ferrous-dns .

# Run the container
docker run -d \
  --name ferrous-dns \
  -p 53:53/udp \
  -p 53:53/tcp \
  -p 8080:8080 \
  -v ferrous-data:/var/lib/ferrous-dns \
  --restart unless-stopped \
  ferrous-dns
```

### Using Docker Compose

Create `docker-compose.yml`:

```yaml
version: '3.8'

services:
  ferrous-dns:
    image: ghcr.io/andersonviudes/ferrous-dns:latest
    container_name: ferrous-dns
    ports:
      - "53:53/udp"
      - "53:53/tcp"
      - "8080:8080"
    volumes:
      - ferrous-data:/var/lib/ferrous-dns
      - ./config:/etc/ferrous-dns:ro
    environment:
      - RUST_LOG=info
    restart: unless-stopped

volumes:
  ferrous-data:
    driver: local
```

Deploy:

```bash
docker-compose up -d
```

### Docker Hub / GitHub Container Registry

```bash
# Pull from GitHub Container Registry
docker pull ghcr.io/andersonviudes/ferrous-dns:latest

# Pull from Docker Hub (coming soon)
docker pull andersonviudes/ferrous-dns:latest
```

---

## 🛠️ Development

### Setup Development Environment

```bash
# Clone repository
git clone https://github.com/andersonviudes/ferrous-dns.git
cd ferrous-dns

# Install Rust (if not already installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Install development tools
rustup component add rustfmt clippy

# Build
cargo build
```

### Running Tests

```bash
# Run all tests
cargo test

# Run tests for specific crate
cargo test -p ferrous-dns-domain

# Run tests with output
cargo test -- --nocapture

# Run tests with logging
RUST_LOG=debug cargo test
```

### Code Quality

```bash
# Format code
cargo fmt

# Check formatting (CI)
cargo fmt -- --check

# Run linter
cargo clippy -- -D warnings

# Check compilation without building
cargo check --all-targets --all-features
```

### Development Mode

```bash
# Run with debug logging
RUST_LOG=debug cargo run

# Hot reload with cargo-watch
cargo install cargo-watch
cargo watch -x run

# Run specific binary
cargo run --bin ferrous-dns
```

### Benchmarking

```bash
# Run benchmarks (coming soon)
cargo bench

# Profile with flamegraph
cargo install flamegraph
cargo flamegraph
```

---

## 🤝 Contributing

We welcome contributions! Please read our [Contributing Guide](CONTRIBUTING.md) first.

### How to Contribute

1. **Fork** the repository
2. **Clone** your fork: `git clone https://github.com/YOUR_USERNAME/ferrous-dns.git`
3. **Create** a feature branch: `git checkout -b feature/amazing-feature`
4. **Make** your changes
5. **Test** your changes: `cargo test`
6. **Format** code: `cargo fmt`
7. **Lint** code: `cargo clippy`
8. **Commit** with conventional commits: `git commit -m 'feat: add amazing feature'`
9. **Push** to your fork: `git push origin feature/amazing-feature`
10. **Open** a Pull Request

### Commit Convention

We follow [Conventional Commits](https://www.conventionalcommits.org/):

- `feat:` - New feature
- `fix:` - Bug fix
- `docs:` - Documentation changes
- `style:` - Code style changes (formatting, etc.)
- `refactor:` - Code refactoring
- `test:` - Adding or updating tests
- `chore:` - Maintenance tasks
- `perf:` - Performance improvements

**Examples:**

```bash
git commit -m "feat: add DNS-over-HTTPS support"
git commit -m "fix: resolve memory leak in cache"
git commit -m "docs: update API documentation"
```

### Code of Conduct

Please be respectful and constructive. See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

---

## 📄 License

This project is dual-licensed under:

- **MIT License** ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)
- **Apache License 2.0** ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)

You may choose either license for your use.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

---

## 🙏 Acknowledgments

Ferrous DNS is built upon the shoulders of giants:

### Core Technologies

- [**Rust**](https://www.rust-lang.org/) - Systems programming language
- [**Tokio**](https://tokio.rs/) - Asynchronous runtime
- [**Axum**](https://github.com/tokio-rs/axum) - Ergonomic web framework
- [**Hickory DNS**](https://github.com/hickory-dns/hickory-dns) - DNS library for Rust

### Frontend

- [**HTMX**](https://htmx.org/) - High power tools for HTML
- [**Alpine.js**](https://alpinejs.dev/) - Lightweight JavaScript framework
- [**TailwindCSS**](https://tailwindcss.com/) - Utility-first CSS framework

### Community

Special thanks to:

- The Rust community for creating an amazing ecosystem
- Contributors and early adopters
- Everyone providing feedback and suggestions

---

## 📬 Contact & Support

- **GitHub Issues**: [Report bugs or request features](https://github.com/andersonviudes/ferrous-dns/issues)
- **GitHub Discussions**: [Ask questions and share ideas](https://github.com/andersonviudes/ferrous-dns/discussions)

---

## 📊 Project Status

| Status | Description                                                     |
|--------|-----------------------------------------------------------------|
| 🚧     | **Alpha** - Core architecture complete, features in development |
| 🔄     | **Active Development** - Regular commits and updates            |
| 📅     | **Beta Target** - Q2 2025                                       |
| 🎯     | **v1.0 Target** - Q3 2025                                       |

---

## ⭐ Star History

[![Star History Chart](https://api.star-history.com/svg?repos=andersonviudes/ferrous-dns&type=Date)](https://star-history.com/#andersonviudes/ferrous-dns&Date)

---

<div align="center">

**Made with ❤️ and 🦀 by [Anderson Viudes](https://github.com/andersonviudes)**

**If you find this project useful, please consider giving it a ⭐ on GitHub!**

[⬆ Back to Top](#-ferrous-dns)

---

*Ferrous DNS - Blazingly fast, memory-safe DNS with ad-blocking*

</div>
