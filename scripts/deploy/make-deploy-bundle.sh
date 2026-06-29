#!/usr/bin/env bash
# Build a single copy-friendly deploy bundle (tarball + install script).
# Copy this ONE file to production — no shared drive mount required on prod.
set -euo pipefail

PROD_HOST="${PROD_HOST:-scaqaa04celadm12.us.oracle.com}"
PROD_USER="${PROD_USER:-maatest}"
PROD_APP_DIR="${PROD_APP_DIR:-/home/maatest/mchafin/MAA_APPS_NEW}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUT_DIR="${1:-$(cd "$SCRIPT_DIR/../.." && pwd)/dist}"

mkdir -p "$OUT_DIR"
BUILD_DIR="$(mktemp -d)"
trap 'rm -rf "$BUILD_DIR"' EXIT

"$SCRIPT_DIR/build-release.sh" "$BUILD_DIR"

RELEASE_TAR="$(ls -1 "$BUILD_DIR"/maa-unity-2*.tar.gz | grep -v latest | head -1)"
BUNDLE_NAME="$(basename "$RELEASE_TAR" .tar.gz)-deploy-bundle"
BUNDLE_DIR="$BUILD_DIR/$BUNDLE_NAME"

mkdir -p "$BUNDLE_DIR"
cp "$RELEASE_TAR" "$BUNDLE_DIR/release.tar.gz"
cp "$SCRIPT_DIR/install-release.sh" "$BUNDLE_DIR/install-release.sh"
cp "$SCRIPT_DIR/install-bundle.sh" "$BUNDLE_DIR/install-bundle.sh"
chmod +x "$BUNDLE_DIR/"*.sh

cat > "$BUNDLE_DIR/DEPLOY.txt" <<EOF
MAA Unity deploy bundle
=======================
Production host: ${PROD_HOST}
Install path:    ${PROD_APP_DIR}
Built:           $(date -u +%Y-%m-%dT%H:%M:%SZ)

STEP 1 — Copy this file to production (from any machine that can reach prod):
  scp ${BUNDLE_NAME}.tar.gz ${PROD_USER}@${PROD_HOST}:~/mchafin/

STEP 2 — On ${PROD_HOST} as ${PROD_USER}:
  cd ~/mchafin
  tar -xzf ${BUNDLE_NAME}.tar.gz
  cd ${BUNDLE_NAME}
  ./install-bundle.sh

STEP 3 — Restart the app:
  export MAA_APP_ROOT=${PROD_APP_DIR}
  export MAA_OUTPUT_DIR=\$MAA_APP_ROOT/output
  # pip install -r \$MAA_APP_ROOT/requirements.txt   # if deps changed
  # restart maa_unified_app.py

Rollback: see install-release.sh output for backup path under ~/mchafin/backups/
EOF

tar -C "$BUILD_DIR" -czf "${OUT_DIR}/${BUNDLE_NAME}.tar.gz" "$BUNDLE_NAME"

echo ""
echo "Deploy bundle ready:"
ls -lh "${OUT_DIR}/${BUNDLE_NAME}.tar.gz"
echo ""
echo "Copy to production:"
echo "  scp ${OUT_DIR}/${BUNDLE_NAME}.tar.gz ${PROD_USER}@${PROD_HOST}:~/mchafin/"
echo ""
echo "Then on ${PROD_HOST}:"
echo "  cd ~/mchafin && tar -xzf ${BUNDLE_NAME}.tar.gz && cd ${BUNDLE_NAME} && ./install-bundle.sh"