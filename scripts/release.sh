#!/usr/bin/env bash

# ============================================================================
# Ferrous DNS - Release Script
# ============================================================================
# Automates the release process:
# 1. Validates git status
# 2. Runs tests
# 3. Bumps version
# 4. Updates CHANGELOG
# 5. Creates git tag
# 6. Pushes to remote
# ============================================================================

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# ============================================================================
# Helper Functions
# ============================================================================

log_info() {
    echo -e "${BLUE}ℹ${NC} $1"
}

log_success() {
    echo -e "${GREEN}✓${NC} $1"
}

log_error() {
    echo -e "${RED}✗${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

# ============================================================================
# Validation Functions
# ============================================================================

check_git_clean() {
    log_info "Checking git status..."
    if [[ -n $(git status --porcelain) ]]; then
        log_error "Working directory is not clean. Commit or stash changes first."
        exit 1
    fi
    log_success "Git working directory is clean"
}

check_main_branch() {
    local current_branch=$(git branch --show-current)
    if [[ "$current_branch" != "main" ]]; then
        log_warning "You are not on the 'main' branch (current: $current_branch)"
        read -p "Continue anyway? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
}

check_tools() {
    log_info "Checking required tools..."
    
    local tools=("cargo" "git" "jq")
    for tool in "${tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            log_error "$tool is not installed"
            exit 1
        fi
    done
    
    log_success "All required tools are installed"
}

# ============================================================================
# Version Management
# ============================================================================

get_current_version() {
    cargo metadata --no-deps --format-version 1 | jq -r '.packages[0].version'
}

validate_version() {
    local version=$1
    if [[ ! $version =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        log_error "Invalid version format: $version (expected: MAJOR.MINOR.PATCH)"
        exit 1
    fi
}

bump_version() {
    local bump_type=$1
    local current_version=$(get_current_version)
    
    log_info "Current version: $current_version"
    log_info "Bump type: $bump_type"
    
    # Use cargo-release if available, otherwise use bump-version.sh
    if command -v cargo-release &> /dev/null; then
        cargo release "$bump_type" --execute --no-confirm
    else
        bash scripts/bump-version.sh "$bump_type"
    fi
    
    local new_version=$(get_current_version)
    log_success "Version bumped to $new_version"
    echo "$new_version"
}

# ============================================================================
# Testing
# ============================================================================

run_tests() {
    log_info "Running test suite..."
    if cargo test --all-features --workspace; then
        log_success "All tests passed"
    else
        log_error "Tests failed"
        exit 1
    fi
}

run_checks() {
    log_info "Running cargo checks..."
    
    if cargo fmt -- --check; then
        log_success "Code formatting is correct"
    else
        log_error "Code formatting issues found. Run: cargo fmt"
        exit 1
    fi
    
    if cargo clippy -- -D warnings; then
        log_success "No clippy warnings"
    else
        log_error "Clippy warnings found"
        exit 1
    fi
}

# ============================================================================
# Changelog
# ============================================================================

update_changelog() {
    log_info "Updating CHANGELOG.md..."
    
    if command -v git-cliff &> /dev/null; then
        git-cliff --tag "$1" --output CHANGELOG.md
        git add CHANGELOG.md
        log_success "CHANGELOG.md updated"
    else
        log_warning "git-cliff not found. Skipping CHANGELOG update."
        log_info "Install with: cargo install git-cliff"
    fi
}

# ============================================================================
# Git Operations
# ============================================================================

create_git_tag() {
    local version=$1
    local tag="v$version"
    
    log_info "Creating git tag: $tag"
    
    git commit -am "chore: release v$version"
    git tag -a "$tag" -m "Release v$version"
    
    log_success "Git tag created: $tag"
}

push_changes() {
    local tag=$1
    
    log_info "Pushing changes to remote..."
    
    git push origin main
    git push origin "$tag"
    
    log_success "Changes pushed to remote"
}

# ============================================================================
# Main Script
# ============================================================================

main() {
    echo ""
    echo "╔═══════════════════════════════════════════╗"
    echo "║       Ferrous DNS - Release Script       ║"
    echo "╚═══════════════════════════════════════════╝"
    echo ""
    
    # Parse arguments
    local bump_type=${1:-patch}
    
    if [[ "$bump_type" != "major" && "$bump_type" != "minor" && "$bump_type" != "patch" ]]; then
        log_error "Invalid bump type: $bump_type"
        echo "Usage: $0 [major|minor|patch]"
        exit 1
    fi
    
    # Pre-flight checks
    check_tools
    check_git_clean
    check_main_branch
    
    # Run tests and checks
    run_tests
    run_checks
    
    # Bump version
    local new_version=$(bump_version "$bump_type")
    
    # Update changelog
    update_changelog "$new_version"
    
    # Create git tag
    create_git_tag "$new_version"
    
    # Push to remote
    log_info "Ready to push changes"
    read -p "Push to remote? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        push_changes "v$new_version"
    else
        log_warning "Changes not pushed. Run manually:"
        echo "  git push origin main"
        echo "  git push origin v$new_version"
    fi
    
    echo ""
    log_success "Release v$new_version completed!"
    echo ""
    log_info "Next steps:"
    echo "  1. GitHub Actions will build and publish the release"
    echo "  2. Docker images will be built and pushed"
    echo "  3. Check: https://github.com/andersonviudes/ferrous-dns/releases"
    echo ""
}

# Run main function
main "$@"
