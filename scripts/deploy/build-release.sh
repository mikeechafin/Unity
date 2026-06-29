#!/usr/bin/env bash
# Build a versioned release tarball for production deploy (no git required on prod).
set -euo pipefail

APP_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$APP_ROOT"

VERSION="$(git describe --tags --always --dirty 2>/dev/null || echo "unknown")"
DATE="$(date -u +%Y%m%d)"
RELEASE_NAME="maa-unity-${DATE}-${VERSION}"
STAGING="/tmp/${RELEASE_NAME}"
TARBALL="${RELEASE_NAME}.tar.gz"

# Default: drop releases on shared drive if mounted
DEFAULT_OUT="/mnt/hgfs/D/UNIFIED/releases"
OUT_DIR="${1:-$DEFAULT_OUT}"

echo "Building release: ${RELEASE_NAME}"
rm -rf "$STAGING"
mkdir -p "$STAGING"

# Copy application tree, excluding secrets/runtime/heavy dirs (same policy as .gitignore)
rsync -a \
  --exclude='.git' \
  --exclude='__pycache__' \
  --exclude='*.pyc' \
  --exclude='.venv' \
  --exclude='venv' \
  --exclude='output' \
  --exclude='encryption_key.txt' \
  --exclude='server.crt' \
  --exclude='server.key' \
  --exclude='*.pem' \
  --exclude='EMCLI' \
  --exclude='OEDA' \
  --exclude='TEST_CONFIG_SCRIPTS' \
  --exclude='static/screenshots' \
  --exclude='fd' \
  --exclude='.env' \
  "$APP_ROOT/" "$STAGING/"

mkdir -p "$STAGING/output"
touch "$STAGING/output/.gitkeep"

cat > "$STAGING/RELEASE.json" <<EOF
{
  "name": "${RELEASE_NAME}",
  "version": "${VERSION}",
  "built_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "git_commit": "$(git rev-parse HEAD 2>/dev/null || echo null)",
  "builder_host": "$(hostname -f 2>/dev/null || hostname)"
}
EOF

mkdir -p "$OUT_DIR"
tar -C /tmp -czf "${OUT_DIR}/${TARBALL}" "$RELEASE_NAME"
ln -sfn "${TARBALL}" "${OUT_DIR}/maa-unity-latest.tar.gz"

echo "Created: ${OUT_DIR}/${TARBALL}"
echo "Latest:  ${OUT_DIR}/maa-unity-latest.tar.gz"
ls -lh "${OUT_DIR}/${TARBALL}"