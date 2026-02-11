# 🚀 Ferrous DNS - Release & Deployment Package

## ✨ COMPLETO + AUTOMATIZADO + CONFIGURÁVEL

Package completo com **imagem Docker Alpine minimalista** (~15-20MB), **ENVs configuráveis**, e automação total integrada ao GitHub Actions.

---

## 🎯 O Que Faz (1 Comando)

```bash
./scripts/release.sh patch
```

**Resultado Automático:**
1. ✅ Resumo dos commits (GitHub Release notes)
2. ✅ CHANGELOG.md atualizado (git-cliff)
3. ✅ 2 binários compilados (amd64 + arm64 Linux)
4. ✅ Docker multi-arch (amd64 + arm64)
5. ✅ Push Docker Hub + GHCR
6. ✅ Tags: latest, v0.1.1, 0.1, 0
7. ✅ Security scans automáticos

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

## 🚀 Quick Start

### 1. Instalar no Projeto

```bash
unzip ferrous-dns-release-deployment.zip
cd ferrous-dns-release-deployment

# Copiar para o projeto
cp -r .github/workflows/* ../ferrous-dns/.github/workflows/
cp -r scripts/* ../ferrous-dns/scripts/
cp -r docker/* ../ferrous-dns/docker/
cp Dockerfile ../ferrous-dns/
cp docker-compose.yml ../ferrous-dns/
cp Makefile ../ferrous-dns/
cp cliff.toml ../ferrous-dns/
cp release.toml ../ferrous-dns/

chmod +x ../ferrous-dns/scripts/*.sh
chmod +x ../ferrous-dns/docker/entrypoint.sh
```

### 2. Configurar Secrets no GitHub

Settings > Secrets and variables > Actions:
- `DOCKERHUB_USERNAME` - Seu username
- `DOCKERHUB_TOKEN` - Token do Docker Hub

**Ver:** `docs/SECRETS_GUIDE.md`

### 3. Criar Release

**Opção A: Via Script (Terminal)** ⚡

```bash
cd ../ferrous-dns
./scripts/release.sh patch
```

**Opção B: Via GitHub Actions (Interface)** 🖱️

1. Vá em `https://github.com/seu-usuario/ferrous-dns/actions`
2. Clique em **"Release"** (menu lateral)
3. Clique em **"Run workflow"** (canto direito)
4. Digite a versão: `v0.1.0`
5. Clique **"Run workflow"**
6. Aguarde ~10 minutos ✅

**Ver guia visual completo:** `docs/RELEASE_VIA_GITHUB_UI.md`

**Resultado (ambas opções):**
```
✨ GitHub Actions faz automaticamente:
   ✅ Resumo dos commits
   ✅ CHANGELOG.md
   ✅ Build 2 binários (amd64, arm64)
   ✅ Docker multi-arch
   ✅ Push Docker Hub + GHCR
   ✅ Tags: latest, v0.1.1, 0.1, 0
```

---

## 📊 O Que É Publicado

### GitHub Release `v0.1.1`

```
Release v0.1.1

📝 Changes:
• feat: add DNS-over-HTTPS support
• fix: resolve cache eviction bug  
• perf: optimize query processing

📦 Assets:
✅ ferrous-dns-linux-amd64.tar.gz (~8MB)
✅ ferrous-dns-linux-amd64.tar.gz.sha256
✅ ferrous-dns-linux-arm64.tar.gz (~7.5MB)
✅ ferrous-dns-linux-arm64.tar.gz.sha256
```

### CHANGELOG.md

```markdown
# Changelog

## [0.1.1] - 2026-02-11

### Features
- Add DNS-over-HTTPS support

### Bug Fixes
- Resolve cache eviction bug

### Performance
- Optimize query processing
```

### Docker Images

**Docker Hub:**
```
andersonviudes/ferrous-dns:latest
andersonviudes/ferrous-dns:v0.1.1
andersonviudes/ferrous-dns:0.1
andersonviudes/ferrous-dns:0
```

**GitHub Container Registry:**
```
ghcr.io/andersonviudes/ferrous-dns:latest
ghcr.io/andersonviudes/ferrous-dns:v0.1.1
ghcr.io/andersonviudes/ferrous-dns:0.1
ghcr.io/andersonviudes/ferrous-dns:0
```

**Todas com:**
- ✅ `linux/amd64`
- ✅ `linux/arm64`

---

## 🔄 Fluxo Completo

```
┌────────────────────────────────────────────────────────────┐
│ 1. Developer: ./scripts/release.sh patch                  │
│    → Tests ✅                                             │
│    → Bump version ✅                                      │
│    → Generate CHANGELOG ✅                                │
│    → Commit + tag (v0.1.1) ✅                             │
│    → Push ✅                                              │
└────────────────────────────────────────────────────────────┘
                         ↓
┌────────────────────────────────────────────────────────────┐
│ 2. GitHub Actions: release.yml                            │
│    → Create GitHub Release ✅                             │
│    → Resumo dos commits ✅                                │
│    → Build ferrous-dns-linux-amd64.tar.gz ✅              │
│    → Build ferrous-dns-linux-arm64.tar.gz ✅              │
│    → Upload assets + SHA256 ✅                            │
│    → Trigger docker.yml ✅                                │
└────────────────────────────────────────────────────────────┘
                         ↓
┌────────────────────────────────────────────────────────────┐
│ 3. GitHub Actions: docker.yml                             │
│    → Build Alpine (amd64 + arm64) ✅                      │
│    → Push Docker Hub ✅                                   │
│    → Push GHCR ✅                                         │
│    → Tags: latest, v0.1.1, 0.1, 0 ✅                      │
│    → Security scans (Trivy) ✅                            │
└────────────────────────────────────────────────────────────┘
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

## 🌍 Multi-Arch Nativo

Funciona automaticamente em:
- ✅ Servidores x64 (Intel/AMD)
- ✅ Apple Silicon (M1/M2/M3/M4)
- ✅ Raspberry Pi 4/5
- ✅ AWS Graviton
- ✅ Oracle Cloud ARM

---

## 📋 Workflows

### 1. CI (ci.yml)
- Format, lint, tests
- Build (Linux + macOS)
- Security audit
- Code coverage

### 2. Release (release.yml) ⭐
- **Resumo dos commits** (GitHub Release notes)
- **CHANGELOG automático** (git-cliff)
- **Build 2 binários:** amd64 + arm64 (MUSL static)
- Upload assets + checksums
- Trigger Docker build

### 3. Docker (docker.yml)
- Build Alpine multi-arch
- Push Docker Hub + GHCR
- Tags automáticas
- Security scans

### 4. PR Validation (pr-validation.yml)
- Conventional Commits
- Breaking changes
- Size labels

---

## 🛠️ Comandos Make

```bash
# Release
make release-patch     # 0.1.0 → 0.1.1
make release-minor     # 0.1.0 → 0.2.0
make release-major     # 0.1.0 → 1.0.0

# Docker
make docker-build      # Build imagem
make docker-compose-up # Start
make docker-logs       # Ver logs

# Dev
make build             # Build release
make test              # Tests
make fmt               # Format
make clippy            # Lint

# Help
make help              # Ver todos
```

---

## 📖 Documentação

- **[docs/CONFIG_GUIDE.md](docs/CONFIG_GUIDE.md)** ⭐ Como configurar (TOML + ENVs)
- **[docs/GITHUB_ACTIONS_INTEGRATION.md](docs/GITHUB_ACTIONS_INTEGRATION.md)** - CI/CD
- **[docs/DOCKER.md](docs/DOCKER.md)** - Docker guide
- **[docs/INSTALLATION.md](docs/INSTALLATION.md)** - Instalação
- **[docs/SECRETS_GUIDE.md](docs/SECRETS_GUIDE.md)** - Secrets

---

## ✨ Características

### 📦 Release
- ✅ 1 comando = release completo
- ✅ Resumo automático dos commits
- ✅ CHANGELOG automático (git-cliff)
- ✅ 2 binários (amd64 + arm64 Linux)
- ✅ Checksums SHA256

### 🐳 Docker
- ✅ Alpine ~15-20MB (75% menor)
- ✅ Multi-arch (amd64 + arm64)
- ✅ ENVs configuráveis (6 variáveis)
- ✅ Valores padrão do código
- ✅ Tags automáticas
- ✅ Security scans

### 🤖 Automação
- ✅ GitHub Actions integrado
- ✅ CI completo
- ✅ Deploy automático
- ✅ Zero configuração manual

---

## 🔐 Secrets Necessários

| Secret | Onde | Obter |
|--------|------|-------|
| `DOCKERHUB_USERNAME` | GitHub Settings > Secrets | Docker Hub |
| `DOCKERHUB_TOKEN` | GitHub Settings > Secrets | hub.docker.com/settings/security |
| `GITHUB_TOKEN` | Automático | GitHub fornece |

---

## 📊 Tamanho das Imagens

```
Alpine:  ███ ~15-20MB  ✅ NOSSA IMAGEM
Debian:  ████████ ~70-80MB

Redução: 75%!
```

---

## 🎯 Próximos Passos

1. ✅ Extrair ZIP
2. ✅ Copiar arquivos para o projeto
3. ✅ Configurar secrets no GitHub
4. ✅ Rodar `./scripts/release.sh patch`
5. ✅ Imagens disponíveis em minutos! 🚀

---

## 💡 Exemplo Completo

```bash
# 1. Extrair
unzip ferrous-dns-release-deployment.zip
cd ferrous-dns-release-deployment

# 2. Instalar
cp -r .github ../ferrous-dns/
cp -r scripts ../ferrous-dns/
cp -r docker ../ferrous-dns/
cp Dockerfile docker-compose.yml Makefile cliff.toml release.toml ../ferrous-dns/

# 3. Configurar secrets no GitHub
# Settings > Secrets > DOCKERHUB_USERNAME + DOCKERHUB_TOKEN

# 4. Release!
cd ../ferrous-dns
chmod +x scripts/*.sh docker/entrypoint.sh
./scripts/release.sh patch

# 5. Usar
docker pull ghcr.io/andersonviudes/ferrous-dns:latest
docker run -d -p 53:53/udp -p 8080:8080 \
  -e FERROUS_LOG_LEVEL=info \
  ghcr.io/andersonviudes/ferrous-dns
```

---

**Tudo automatizado, configurável e pronto para produção!** 🎉

---

## 🎁 Bonus: Entrypoint Script

O entrypoint converte ENVs em CLI args automaticamente:

```bash
# ENVs → CLI args
FERROUS_DNS_PORT=5353 → --dns-port 5353
FERROUS_WEB_PORT=3000 → --web-port 3000
FERROUS_LOG_LEVEL=debug → --log-level debug
```

Veja: `docker/entrypoint.sh`
