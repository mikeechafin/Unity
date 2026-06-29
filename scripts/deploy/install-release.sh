#!/usr/bin/env bash
# Install a Unity release tarball onto production, preserving local secrets and logs.
#
# Usage:
#   install-release.sh <tarball> [target_dir]
#
# Example:
#   ./install-release.sh /mnt/hgfs/D/UNIFIED/releases/maa-unity-latest.tar.gz \
#       /home/maatest/mchafin/MAA_APPS_NEW
set -euo pipefail

TARBALL="${1:?Usage: install-release.sh <tarball> [target_dir]}"
TARGET="${2:-/home/maatest/mchafin/MAA_APPS_NEW}"
STAGING="/tmp/maa-unity-install-$$"
BACKUP_ROOT="$(dirname "$TARGET")/backups"

if [[ ! -f "$TARBALL" ]]; then
  echo "ERROR: tarball not found: $TARBALL" >&2
  exit 1
fi

echo "Installing $(basename "$TARBALL") -> $TARGET"

# Backup current production tree (code only, skip output)
TS="$(date -u +%Y%m%d_%H%M%S)"
BACKUP_DIR="${BACKUP_ROOT}/MAA_APPS_NEW_${TS}"
mkdir -p "$BACKUP_ROOT"
if [[ -d "$TARGET" ]]; then
  echo "Backing up current install to $BACKUP_DIR"
  mkdir -p "$BACKUP_DIR"
  rsync -a \
    --exclude='output' \
    --exclude='__pycache__' \
    "$TARGET/" "$BACKUP_DIR/"
fi

rm -rf "$STAGING"
mkdir -p "$STAGING"
tar -xzf "$TARBALL" -C "$STAGING"
RELEASE_DIR="$(find "$STAGING" -mindepth 1 -maxdepth 1 -type d | head -1)"
if [[ -z "$RELEASE_DIR" ]]; then
  echo "ERROR: invalid tarball layout" >&2
  exit 1
fi

mkdir -p "$TARGET"

# Deploy code; never overwrite production secrets, certs, or logs
rsync -a --delete \
  --exclude='output/' \
  --exclude='encryption_key.txt' \
  --exclude='server.crt' \
  --exclude='server.key' \
  --exclude='*.pem' \
  --exclude='EMCLI/' \
  --exclude='OEDA/' \
  --exclude='TEST_CONFIG_SCRIPTS/' \
  "$RELEASE_DIR/" "$TARGET/"

mkdir -p "$TARGET/output"

if [[ -f "$RELEASE_DIR/RELEASE.json" ]]; then
  cp "$RELEASE_DIR/RELEASE.json" "$TARGET/RELEASE.json"
  echo "Installed version:"
  cat "$TARGET/RELEASE.json"
fi

rm -rf "$STAGING"

echo ""
echo "Install complete."
echo "  Target:  $TARGET"
echo "  Backup:  $BACKUP_DIR"
echo ""
echo "Next steps on production:"
echo "  1. export MAA_APP_ROOT=$TARGET"
echo "  2. export MAA_OUTPUT_DIR=$TARGET/output"
echo "  3. pip install -r $TARGET/requirements.txt   # if dependencies changed"
echo "  4. Restart maa_unified_app.py / scheduler"
echo ""
echo "Rollback: rsync -a $BACKUP_DIR/ $TARGET/  (then restart)"