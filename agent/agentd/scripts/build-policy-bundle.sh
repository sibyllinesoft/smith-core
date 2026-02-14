#!/usr/bin/env bash
#
# Build OPA policy bundles for agentd
#
# This script packages all Rego policies and data files into
# an OPA-compatible bundle that can be loaded by both:
# - OPA server (for Envoy ext_authz)
# - agentd (via regorus crate)
#
# Usage:
#   ./scripts/build-policy-bundle.sh
#   ./scripts/build-policy-bundle.sh --output ./custom-output

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Default output directory
OUTPUT_DIR="${PROJECT_ROOT}/build/bundles"

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --output|-o)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        --help|-h)
            echo "Usage: $0 [--output DIR]"
            echo "Build OPA policy bundles for agentd"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Create temporary build directory
BUILD_TMP=$(mktemp -d)
trap "rm -rf $BUILD_TMP" EXIT

echo "Building agentd policy bundle..."
echo "  Source: ${PROJECT_ROOT}/policy"
echo "  Output: ${OUTPUT_DIR}"

# Copy policy files
echo "  Copying policy files..."
mkdir -p "$BUILD_TMP/agentd"
cp -r "${PROJECT_ROOT}/policy/"*.rego "$BUILD_TMP/agentd/" 2>/dev/null || true

# Copy data files
if [ -d "${PROJECT_ROOT}/policy/data" ]; then
    echo "  Copying data files..."
    cp -r "${PROJECT_ROOT}/policy/data/"*.json "$BUILD_TMP/" 2>/dev/null || true
fi

# Create bundle manifest
echo "  Creating manifest..."
cat > "$BUILD_TMP/.manifest" << EOF
{
  "revision": "$(git -C "$PROJECT_ROOT" rev-parse --short HEAD 2>/dev/null || echo 'dev')",
  "roots": ["agentd"],
  "metadata": {
    "build_time": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
    "version": "1.0.0"
  }
}
EOF

# Build the bundle tarball
echo "  Creating bundle tarball..."
BUNDLE_FILE="${OUTPUT_DIR}/agentd-bundle.tar.gz"
(cd "$BUILD_TMP" && tar -czf "$BUNDLE_FILE" .)

echo "  Bundle created: $BUNDLE_FILE"
echo "  Bundle size: $(du -h "$BUNDLE_FILE" | cut -f1)"

# Validate bundle with OPA if available
if command -v opa &> /dev/null; then
    echo "  Validating bundle with OPA..."
    if opa build -b "$BUILD_TMP" -o /dev/null 2>/dev/null; then
        echo "  Bundle validation: OK"
    else
        echo "  Bundle validation: WARNING - OPA validation failed"
    fi
else
    echo "  Skipping OPA validation (opa not installed)"
fi

# Also create an uncompressed bundle for development
echo "  Creating development bundle (uncompressed)..."
DEV_BUNDLE_DIR="${OUTPUT_DIR}/agentd-bundle"
rm -rf "$DEV_BUNDLE_DIR"
cp -r "$BUILD_TMP" "$DEV_BUNDLE_DIR"
echo "  Development bundle: $DEV_BUNDLE_DIR"

echo ""
echo "Bundle build complete!"
echo ""
echo "To use with OPA server:"
echo "  opa run --server --bundle ${BUNDLE_FILE}"
echo ""
echo "To use with Envoy + OPA (docker-compose):"
echo "  docker compose -f infra/compose/docker-compose.yaml up"
