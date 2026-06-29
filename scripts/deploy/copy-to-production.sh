#!/usr/bin/env bash
# Build deploy bundle and scp to production (if SSH from this host works).
set -euo pipefail

PROD_HOST="${PROD_HOST:-scaqaa04celadm12.us.oracle.com}"
PROD_USER="${PROD_USER:-maatest}"
REMOTE_DIR="${REMOTE_DIR:-~/mchafin}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DIST_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)/dist"

"$SCRIPT_DIR/make-deploy-bundle.sh" "$DIST_DIR"

BUNDLE="$(ls -1t "$DIST_DIR"/*-deploy-bundle.tar.gz | head -1)"
BASENAME="$(basename "$BUNDLE")"

echo "Copying $BASENAME -> ${PROD_USER}@${PROD_HOST}:${REMOTE_DIR}/"
scp "$BUNDLE" "${PROD_USER}@${PROD_HOST}:${REMOTE_DIR}/"

echo ""
echo "SSH to production and install:"
echo "  ssh ${PROD_USER}@${PROD_HOST}"
echo "  cd ~/mchafin && tar -xzf ${BASENAME} && cd ${BASENAME%.tar.gz} && ./install-bundle.sh"