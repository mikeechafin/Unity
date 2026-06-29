#!/usr/bin/env bash
# Build release and copy to shared drive (one command from dev VM).
set -euo pipefail

SHARED_RELEASES="${1:-/mnt/hgfs/D/UNIFIED/releases}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

"$SCRIPT_DIR/build-release.sh" "$SHARED_RELEASES"
cp "$SCRIPT_DIR/install-release.sh" "$SHARED_RELEASES/install-release.sh"
chmod +x "$SHARED_RELEASES/install-release.sh"

echo ""
echo "Ready for production. On the app server run:"
echo "  $SHARED_RELEASES/install-release.sh $SHARED_RELEASES/maa-unity-latest.tar.gz /home/maatest/mchafin/MAA_APPS_NEW"