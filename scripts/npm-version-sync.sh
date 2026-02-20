#!/usr/bin/env bash
# Sync smith-services npm package versions with the workspace version from Cargo.toml.
# Usage: scripts/npm-version-sync.sh [VERSION]
#   If VERSION is omitted, reads from Cargo.toml workspace.package.version.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

VERSION="${1:-}"
if [ -z "$VERSION" ]; then
  VERSION="$(grep -A2 '^\[workspace\.package\]' Cargo.toml | grep '^version' | head -1 | sed 's/.*= *"\(.*\)"/\1/')"
fi

if [ -z "$VERSION" ]; then
  echo "Error: could not determine version" >&2
  exit 1
fi

echo "Syncing smith-services npm packages to version $VERSION"

PACKAGES=(
  npm/smith-services
  npm/smith-services-linux-x64
  npm/smith-services-darwin-arm64
)

for pkg in "${PACKAGES[@]}"; do
  if [ -f "$pkg/package.json" ]; then
    # Update the package's own version
    tmp=$(mktemp)
    sed "s/\"version\": \"[^\"]*\"/\"version\": \"$VERSION\"/" "$pkg/package.json" > "$tmp"
    mv "$tmp" "$pkg/package.json"
    echo "  $pkg -> $VERSION"
  fi
done

# Update optionalDependencies versions in the root package
ROOT_PKG="npm/smith-services/package.json"
if [ -f "$ROOT_PKG" ]; then
  tmp=$(mktemp)
  sed "s/\"@sibyllinesoft\/smith-services-\([^\"]*\)\": \"[^\"]*\"/\"@sibyllinesoft\/smith-services-\1\": \"$VERSION\"/" "$ROOT_PKG" > "$tmp"
  mv "$tmp" "$ROOT_PKG"
  echo "  Updated optionalDependencies in $ROOT_PKG"
fi

echo "Done."
