#!/usr/bin/env bash
set -euo pipefail

VERSION="${1:?Usage: npm-version-sync.sh <version>}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
NPM_DIR="${SCRIPT_DIR}/../npm"

PACKAGES=(
  agentd
  agentd-linux-x64
  agentd-linux-arm64
  agentd-darwin-x64
  agentd-darwin-arm64
)

for pkg in "${PACKAGES[@]}"; do
  PKG_JSON="${NPM_DIR}/${pkg}/package.json"
  if [[ ! -f "${PKG_JSON}" ]]; then
    echo "ERROR: ${PKG_JSON} not found" >&2
    exit 1
  fi

  echo "Updating ${pkg} to ${VERSION}..."
  node -e "
    const fs = require('fs');
    const pkg = JSON.parse(fs.readFileSync('${PKG_JSON}', 'utf8'));
    pkg.version = '${VERSION}';
    if (pkg.optionalDependencies) {
      for (const dep of Object.keys(pkg.optionalDependencies)) {
        pkg.optionalDependencies[dep] = '${VERSION}';
      }
    }
    fs.writeFileSync('${PKG_JSON}', JSON.stringify(pkg, null, 2) + '\n');
  "
done

echo "All packages updated to ${VERSION}"
