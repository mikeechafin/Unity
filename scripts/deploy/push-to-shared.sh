#!/usr/bin/env bash
# Optional: also drop bundle on shared drive for manual pickup (prod cannot mount share).
set -euo pipefail

SHARED_RELEASES="${1:-/mnt/hgfs/D/UNIFIED/releases}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

"$SCRIPT_DIR/make-deploy-bundle.sh"

BUNDLE="$(ls -1t "$(cd "$SCRIPT_DIR/../.." && pwd)/dist"/*-deploy-bundle.tar.gz | head -1)"
if [[ -d "$SHARED_RELEASES" ]]; then
  mkdir -p "$SHARED_RELEASES"
  cp "$BUNDLE" "$SHARED_RELEASES/"
  cp "$SCRIPT_DIR/install-bundle.sh" "$SHARED_RELEASES/"
  cp "$SCRIPT_DIR/install-release.sh" "$SHARED_RELEASES/"
  chmod +x "$SHARED_RELEASES/"*.sh
  echo "Also copied to shared drive: $SHARED_RELEASES/$(basename "$BUNDLE")"
else
  echo "Shared drive not mounted — bundle is in dist/ only."
fi

echo ""
echo "Production: scaqaa04celadm12.us.oracle.com"
echo "Copy bundle there, then: tar -xzf <bundle> && cd <dir> && ./install-bundle.sh"