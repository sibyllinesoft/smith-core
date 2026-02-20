#!/usr/bin/env bash
# Publish smith-services npm packages (platform packages first, then root).
# Usage: scripts/npm-publish.sh [--dry-run]
set -euo pipefail

DRY_RUN=""
if [ "${1:-}" = "--dry-run" ]; then
  DRY_RUN="--dry-run"
fi

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

# Publish platform packages first (they must exist before the root package)
PLATFORM_PACKAGES=(
  npm/smith-services-linux-x64
  npm/smith-services-darwin-arm64
)

for pkg in "${PLATFORM_PACKAGES[@]}"; do
  if [ -f "$pkg/package.json" ]; then
    echo "Publishing $pkg ..."
    (cd "$pkg" && npm publish --provenance --access public $DRY_RUN)
  fi
done

# Publish root package last
echo "Publishing npm/smith-services ..."
(cd npm/smith-services && npm publish --provenance --access public $DRY_RUN)

echo "All smith-services packages published."
