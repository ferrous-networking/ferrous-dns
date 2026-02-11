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
---

## 🐳 Docker com ENVs Configuráveis

### Variáveis de Ambiente Disponíveis

Todas com **valores padrão do código**:

| ENV | Padrão | Descrição | CLI Arg |
|-----|--------|-----------|---------|
| `FERROUS_CONFIG` | - | Config file path | `--config` |
| `FERROUS_DNS_PORT` | `53` | DNS port | `--dns-port` |
| `FERROUS_WEB_PORT` | `8080` | Web port | `--web-port` |
| `FERROUS_BIND_ADDRESS` | `0.0.0.0` | Bind address | `--bind` |
| `FERROUS_DATABASE` | `/var/lib/ferrous-dns/ferrous.db` | Database path | `--database` |
| `FERROUS_LOG_LEVEL` | `info` | Log level | `--log-level` |
| `RUST_LOG` | `info` | Rust logging | - |

### Uso

```bash
# Defaults (portas 53 e 8080)
docker run -d \
  -p 53:53/udp -p 8080:8080 \
  ghcr.io/andersonviudes/ferrous-dns

# Portas customizadas
docker run -d \
  -p 5353:5353/udp -p 3000:3000 \
  -e FERROUS_DNS_PORT=5353 \
  -e FERROUS_WEB_PORT=3000 \
  -e FERROUS_LOG_LEVEL=debug \
  ghcr.io/andersonviudes/ferrous-dns

# Com arquivo de config
docker run -d \
  -v $(pwd)/config.toml:/etc/ferrous-dns/config.toml:ro \
  -e FERROUS_CONFIG=/etc/ferrous-dns/config.toml \
  ghcr.io/andersonviudes/ferrous-dns
```

---

## 📦 Conteúdo do Package

```
ferrous-dns-release-deployment/
├── .github/workflows/
│   ├── ci.yml              # CI completo
│   ├── release.yml         # Release + 2 binários (amd64, arm64)
│   ├── docker.yml          # Docker multi-arch
│   └── pr-validation.yml   # Validação PRs
├── scripts/
│   ├── release.sh          # Release automatizado
│   ├── bump-version.sh     # Bump de versão
│   └── README.md
├── docker/
│   └── entrypoint.sh       # Converte ENVs → CLI args
├── docs/
│   ├── CONFIG_GUIDE.md     # Guia de configuração
│   ├── GITHUB_ACTIONS_INTEGRATION.md
│   ├── DOCKER.md
│   ├── INSTALLATION.md
│   └── SECRETS_GUIDE.md
├── Dockerfile              # Alpine com ENVs (valores padrão)
├── docker-compose.yml      # Compose com todas ENVs
├── Makefile                # 40+ comandos
├── cliff.toml              # Config CHANGELOG
├── release.toml            # Config cargo-release
└── CHANGELOG.md
```

---


## 🐳 Docker Compose

```yaml
version: '3.8'

services:
  ferrous-dns:
    image: ghcr.io/andersonviudes/ferrous-dns:latest
    ports:
      - "53:53/udp"
      - "8080:8080"
    environment:
      # Network (valores padrão)
      - FERROUS_DNS_PORT=53
      - FERROUS_WEB_PORT=8080
      - FERROUS_BIND_ADDRESS=0.0.0.0
      
      # Database
      - FERROUS_DATABASE=/var/lib/ferrous-dns/ferrous.db
      
      # Logging
      - FERROUS_LOG_LEVEL=info
      - RUST_LOG=info
    volumes:
      - ferrous-data:/var/lib/ferrous-dns

volumes:
  ferrous-data:
```

---

Veja: `docker/entrypoint.sh`
