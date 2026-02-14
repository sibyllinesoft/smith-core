#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
NPM_DIR="${SCRIPT_DIR}/../npm"

MAX_RETRIES=3
RETRY_DELAY=10

publish_with_retry() {
  local pkg_dir="$1"
  local attempt=1

  while [[ ${attempt} -le ${MAX_RETRIES} ]]; do
    echo "Publishing $(basename "${pkg_dir}") (attempt ${attempt}/${MAX_RETRIES})..."
    if npm publish "${pkg_dir}" --provenance --access public; then
      echo "Successfully published $(basename "${pkg_dir}")"
      return 0
    fi
    echo "Publish failed, retrying in ${RETRY_DELAY}s..."
    sleep "${RETRY_DELAY}"
    attempt=$((attempt + 1))
  done

  echo "ERROR: Failed to publish $(basename "${pkg_dir}") after ${MAX_RETRIES} attempts" >&2
  return 1
}

# Publish platform packages that have a binary present
published=0
for pkg_dir in "${NPM_DIR}"/agentd-*/; do
  if [[ -x "${pkg_dir}/agentd" ]]; then
    publish_with_retry "${pkg_dir}"
    published=$((published + 1))
  else
    echo "Skipping $(basename "${pkg_dir}") (no binary)"
  fi
done

if [[ ${published} -eq 0 ]]; then
  echo "ERROR: No platform packages had binaries to publish" >&2
  exit 1
fi

# Wait for registry to propagate platform packages
echo "Waiting 30s for registry propagation..."
sleep 30

# Publish the main wrapper package
publish_with_retry "${NPM_DIR}/agentd"

echo "All npm packages published successfully"
