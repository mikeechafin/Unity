#!/usr/bin/env bash
# Run ON the production server after copying the deploy bundle.
# Extracts release.tar.gz and installs to MAA_APPS_NEW.
set -euo pipefail

BUNDLE_DIR="$(cd "$(dirname "$0")" && pwd)"
TARGET="${1:-/home/maatest/mchafin/MAA_APPS_NEW}"

if [[ ! -f "$BUNDLE_DIR/release.tar.gz" ]]; then
  echo "ERROR: release.tar.gz not found in $BUNDLE_DIR" >&2
  exit 1
fi

echo "=== MAA Unity bundle install ==="
cat "$BUNDLE_DIR/DEPLOY.txt" 2>/dev/null || true
echo ""

"$BUNDLE_DIR/install-release.sh" "$BUNDLE_DIR/release.tar.gz" "$TARGET"