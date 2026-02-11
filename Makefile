# ============================================================================
# Ferrous DNS - Makefile
# ============================================================================
# Automates common development and deployment tasks
# Usage: make [target]
# ============================================================================

.PHONY: help build test clean install run dev docker release

# Default target
.DEFAULT_GOAL := help

# Variables
CARGO := cargo
DOCKER := docker
DOCKER_COMPOSE := docker-compose
IMAGE_NAME := ferrous-dns
VERSION := $(shell grep '^version = ' Cargo.toml | head -1 | sed 's/version = "\(.*\)"/\1/')

# Colors for output
BLUE := \033[0;34m
GREEN := \033[0;32m
YELLOW := \033[1;33m
RED := \033[0;31m
NC := \033[0m # No Color

# ============================================================================
# Help
# ============================================================================

help: ## Show this help message
	@echo "$(BLUE)Ferrous DNS - Available Commands$(NC)"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  $(GREEN)%-20s$(NC) %s\n", $$1, $$2}'
	@echo ""

# ============================================================================
# Development
# ============================================================================

build: ## Build the project in release mode
	@echo "$(BLUE)Building Ferrous DNS...$(NC)"
	$(CARGO) build --release
	@echo "$(GREEN)✓ Build completed$(NC)"

build-dev: ## Build the project in debug mode
	@echo "$(BLUE)Building Ferrous DNS (debug)...$(NC)"
	$(CARGO) build
	@echo "$(GREEN)✓ Build completed$(NC)"

test: ## Run all tests
	@echo "$(BLUE)Running tests...$(NC)"
	$(CARGO) test --all-features --workspace
	@echo "$(GREEN)✓ Tests passed$(NC)"

test-unit: ## Run unit tests only
	@echo "$(BLUE)Running unit tests...$(NC)"
	$(CARGO) test --lib --all-features --workspace
	@echo "$(GREEN)✓ Unit tests passed$(NC)"

test-integration: ## Run integration tests only
	@echo "$(BLUE)Running integration tests...$(NC)"
	$(CARGO) test --test '*' --all-features --workspace
	@echo "$(GREEN)✓ Integration tests passed$(NC)"

bench: ## Run benchmarks
	@echo "$(BLUE)Running benchmarks...$(NC)"
	$(CARGO) bench
	@echo "$(GREEN)✓ Benchmarks completed$(NC)"

# ============================================================================
# Code Quality
# ============================================================================

fmt: ## Format code
	@echo "$(BLUE)Formatting code...$(NC)"
	$(CARGO) fmt --all
	@echo "$(GREEN)✓ Code formatted$(NC)"

fmt-check: ## Check code formatting
	@echo "$(BLUE)Checking code formatting...$(NC)"
	$(CARGO) fmt --all -- --check
	@echo "$(GREEN)✓ Code formatting is correct$(NC)"

clippy: ## Run clippy lints
	@echo "$(BLUE)Running clippy...$(NC)"
	$(CARGO) clippy --all-targets --all-features -- -D warnings
	@echo "$(GREEN)✓ Clippy passed$(NC)"

check: ## Check compilation without building
	@echo "$(BLUE)Checking compilation...$(NC)"
	$(CARGO) check --all-targets --all-features
	@echo "$(GREEN)✓ Check completed$(NC)"

audit: ## Security audit
	@echo "$(BLUE)Running security audit...$(NC)"
	$(CARGO) audit
	@echo "$(GREEN)✓ Security audit completed$(NC)"

# ============================================================================
# Running
# ============================================================================

run: ## Run the application in release mode
	@echo "$(BLUE)Running Ferrous DNS...$(NC)"
	$(CARGO) run --release

run-dev: ## Run the application in debug mode
	@echo "$(BLUE)Running Ferrous DNS (debug)...$(NC)"
	RUST_LOG=debug $(CARGO) run

watch: ## Watch for changes and rebuild
	@echo "$(BLUE)Watching for changes...$(NC)"
	$(CARGO) watch -x run

# ============================================================================
# Installation
# ============================================================================

install: ## Install the binary
	@echo "$(BLUE)Installing Ferrous DNS...$(NC)"
	$(CARGO) install --path crates/cli
	@echo "$(GREEN)✓ Installation completed$(NC)"

uninstall: ## Uninstall the binary
	@echo "$(BLUE)Uninstalling Ferrous DNS...$(NC)"
	$(CARGO) uninstall ferrous-dns
	@echo "$(GREEN)✓ Uninstallation completed$(NC)"

# ============================================================================
# Cleaning
# ============================================================================

clean: ## Clean build artifacts
	@echo "$(BLUE)Cleaning build artifacts...$(NC)"
	$(CARGO) clean
	@echo "$(GREEN)✓ Clean completed$(NC)"

clean-all: clean ## Clean all generated files
	@echo "$(BLUE)Cleaning all generated files...$(NC)"
	rm -rf target/
	rm -rf data/
	rm -rf logs/
	rm -f *.db *.sqlite
	@echo "$(GREEN)✓ Deep clean completed$(NC)"

# ============================================================================
# Documentation
# ============================================================================

doc: ## Generate documentation
	@echo "$(BLUE)Generating documentation...$(NC)"
	$(CARGO) doc --no-deps --all-features --workspace
	@echo "$(GREEN)✓ Documentation generated$(NC)"

doc-open: ## Generate and open documentation
	@echo "$(BLUE)Generating and opening documentation...$(NC)"
	$(CARGO) doc --no-deps --all-features --workspace --open

# ============================================================================
# Docker
# ============================================================================

docker-build: ## Build Docker image
	@echo "$(BLUE)Building Docker image...$(NC)"
	$(DOCKER) build -t $(IMAGE_NAME):$(VERSION) -t $(IMAGE_NAME):latest .
	@echo "$(GREEN)✓ Docker image built$(NC)"

docker-run: ## Run Docker container
	@echo "$(BLUE)Running Docker container...$(NC)"
	$(DOCKER) run -d \
		--name ferrous-dns \
		-p 53:53/udp \
		-p 53:53/tcp \
		-p 8080:8080 \
		-v ferrous-data:/var/lib/ferrous-dns \
		$(IMAGE_NAME):latest
	@echo "$(GREEN)✓ Container started$(NC)"

docker-stop: ## Stop Docker container
	@echo "$(BLUE)Stopping Docker container...$(NC)"
	$(DOCKER) stop ferrous-dns
	$(DOCKER) rm ferrous-dns
	@echo "$(GREEN)✓ Container stopped$(NC)"

docker-logs: ## View Docker container logs
	@echo "$(BLUE)Viewing container logs...$(NC)"
	$(DOCKER) logs -f ferrous-dns

docker-compose-up: ## Start services with docker-compose
	@echo "$(BLUE)Starting services with docker-compose...$(NC)"
	$(DOCKER_COMPOSE) up -d
	@echo "$(GREEN)✓ Services started$(NC)"

docker-compose-down: ## Stop services with docker-compose
	@echo "$(BLUE)Stopping services with docker-compose...$(NC)"
	$(DOCKER_COMPOSE) down
	@echo "$(GREEN)✓ Services stopped$(NC)"

docker-compose-logs: ## View docker-compose logs
	@echo "$(BLUE)Viewing docker-compose logs...$(NC)"
	$(DOCKER_COMPOSE) logs -f

# ============================================================================
# Release
# ============================================================================

release-patch: ## Create patch release (0.0.X)
	@echo "$(BLUE)Creating patch release...$(NC)"
	./scripts/release.sh patch

release-minor: ## Create minor release (0.X.0)
	@echo "$(BLUE)Creating minor release...$(NC)"
	./scripts/release.sh minor

release-major: ## Create major release (X.0.0)
	@echo "$(BLUE)Creating major release...$(NC)"
	./scripts/release.sh major

version: ## Show current version
	@echo "$(GREEN)Current version: $(VERSION)$(NC)"

changelog: ## Generate CHANGELOG
	@echo "$(BLUE)Generating CHANGELOG...$(NC)"
	git-cliff --tag v$(VERSION) --output CHANGELOG.md
	@echo "$(GREEN)✓ CHANGELOG generated$(NC)"

# ============================================================================
# CI/CD
# ============================================================================

ci: fmt-check clippy test ## Run CI checks locally
	@echo "$(GREEN)✓ All CI checks passed$(NC)"

pre-commit: fmt clippy test ## Run pre-commit checks
	@echo "$(GREEN)✓ Pre-commit checks passed$(NC)"

# ============================================================================
# Utilities
# ============================================================================

deps: ## Check for outdated dependencies
	@echo "$(BLUE)Checking for outdated dependencies...$(NC)"
	$(CARGO) outdated

update: ## Update dependencies
	@echo "$(BLUE)Updating dependencies...$(NC)"
	$(CARGO) update
	@echo "$(GREEN)✓ Dependencies updated$(NC)"

tree: ## Show dependency tree
	@echo "$(BLUE)Dependency tree:$(NC)"
	$(CARGO) tree

bloat: ## Find what's taking up space in the binary
	@echo "$(BLUE)Analyzing binary size...$(NC)"
	$(CARGO) bloat --release

# ============================================================================
# Development Tools
# ============================================================================

install-tools: ## Install development tools
	@echo "$(BLUE)Installing development tools...$(NC)"
	$(CARGO) install cargo-watch
	$(CARGO) install cargo-outdated
	$(CARGO) install cargo-tree
	$(CARGO) install cargo-bloat
	$(CARGO) install cargo-audit
	$(CARGO) install git-cliff
	$(CARGO) install cargo-release
	@echo "$(GREEN)✓ Tools installed$(NC)"
