#!/usr/bin/env bash

# ============================================================================
# Ferrous DNS - Version Bump Script
# ============================================================================
# Updates version in all Cargo.toml files in the workspace
# Usage: ./bump-version.sh [major|minor|patch|VERSION]
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

# ============================================================================
# Version Parsing
# ============================================================================

parse_version() {
    local version=$1
    local IFS='.'
    read -ra parts <<< "$version"
    
    if [[ ${#parts[@]} -ne 3 ]]; then
        log_error "Invalid version format: $version"
        exit 1
    fi
    
    MAJOR=${parts[0]}
    MINOR=${parts[1]}
    PATCH=${parts[2]}
}

get_current_version() {
    local cargo_toml="Cargo.toml"
    
    if [[ ! -f "$cargo_toml" ]]; then
        log_error "Cargo.toml not found in current directory"
        exit 1
    fi
    
    # Extract version from workspace
    grep '^version = ' "$cargo_toml" | head -1 | sed 's/version = "\(.*\)"/\1/'
}

bump_major() {
    local version=$1
    parse_version "$version"
    echo "$((MAJOR + 1)).0.0"
}

bump_minor() {
    local version=$1
    parse_version "$version"
    echo "${MAJOR}.$((MINOR + 1)).0"
}

bump_patch() {
    local version=$1
    parse_version "$version"
    echo "${MAJOR}.${MINOR}.$((PATCH + 1))"
}

# ============================================================================
# Version Update
# ============================================================================

update_cargo_toml() {
    local file=$1
    local old_version=$2
    local new_version=$3
    
    if [[ ! -f "$file" ]]; then
        log_error "File not found: $file"
        return 1
    fi
    
    # Update version in file
    if [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS
        sed -i '' "s/version = \"$old_version\"/version = \"$new_version\"/g" "$file"
    else
        # Linux
        sed -i "s/version = \"$old_version\"/version = \"$new_version\"/g" "$file"
    fi
    
    log_success "Updated: $file"
}

update_all_versions() {
    local old_version=$1
    local new_version=$2
    
    log_info "Updating version from $old_version to $new_version"
    
    # Update workspace Cargo.toml
    update_cargo_toml "Cargo.toml" "$old_version" "$new_version"
    
    # Update all crate Cargo.toml files
    local crates=(
        "crates/domain/Cargo.toml"
        "crates/application/Cargo.toml"
        "crates/infrastructure/Cargo.toml"
        "crates/api/Cargo.toml"
        "crates/cli/Cargo.toml"
    )
    
    for crate_toml in "${crates[@]}"; do
        if [[ -f "$crate_toml" ]]; then
            update_cargo_toml "$crate_toml" "$old_version" "$new_version"
        fi
    done
    
    log_success "All versions updated to $new_version"
}

# ============================================================================
# Validation
# ============================================================================

validate_version_format() {
    local version=$1
    if [[ ! $version =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        log_error "Invalid version format: $version (expected: MAJOR.MINOR.PATCH)"
        exit 1
    fi
}

# ============================================================================
# Main Script
# ============================================================================

main() {
    local bump_type=$1
    local current_version=$(get_current_version)
    local new_version
    
    log_info "Current version: $current_version"
    
    case "$bump_type" in
        major)
            new_version=$(bump_major "$current_version")
            ;;
        minor)
            new_version=$(bump_minor "$current_version")
            ;;
        patch)
            new_version=$(bump_patch "$current_version")
            ;;
        *)
            # Assume it's a specific version
            new_version=$bump_type
            validate_version_format "$new_version"
            ;;
    esac
    
    log_info "New version: $new_version"

    # Update all files
    update_all_versions "$current_version" "$new_version"
    
    echo ""
    log_success "Version bump completed!"
    log_info "Don't forget to:"
    echo "  1. Run: cargo check"
    echo "  2. Commit changes: git commit -am 'chore: bump version to $new_version'"
    echo "  3. Create tag: git tag v$new_version"
}

# ============================================================================
# Entry Point
# ============================================================================

if [[ $# -eq 0 ]]; then
    log_error "Usage: $0 [major|minor|patch|VERSION]"
    echo ""
    echo "Examples:"
    echo "  $0 patch      # 0.1.0 -> 0.1.1"
    echo "  $0 minor      # 0.1.0 -> 0.2.0"
    echo "  $0 major      # 0.1.0 -> 1.0.0"
    echo "  $0 1.2.3      # Set specific version"
    exit 1
fi

main "$1"
