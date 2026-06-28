# Filename: test_db_ssh_wrapper.sh
# Version: 2026-04-09 v1.3.0
# Changes: Forced verbose -v SSH test on EVERY node unconditionally + explicit env prefix for patchmgr + full per-node log dump. Guarantees we see exact SSH error for scaqal02adm02.
#!/bin/bash
set -e

STAGING_DIR="/home/maatest/mchafin/TEST_CONFIG_SCRIPTS/PATCHING"
MAA_SSH_KEY="/home/maatest/.ssh/id_ed25519_maa"

if [ $# -lt 2 ]; then
  echo "Usage: $0 <patch_version> <list_file>"
  echo "Example: $0 25.2.90.0.0.260409.1 /tmp/dbnodes.list"
  exit 1
fi

VERSION=$1
LIST_FILE=$2
PATCH_DIR="${STAGING_DIR}/dbserver_patch_${VERSION}"
ZIP_NAME="exadata_ol8_${VERSION}_Linux-x86-64.zip"
REPO_PATH="../${ZIP_NAME}"
LOG_DIR="${STAGING_DIR}/cli_logs_database_$(date +%Y%m%d_%H%M%S)"

if [ ! -d "$PATCH_DIR" ]; then
  echo "ERROR: Patch directory $PATCH_DIR does not exist"
  exit 1
fi

if [ ! -f "$LIST_FILE" ]; then
  echo "ERROR: List file $LIST_FILE does not exist"
  exit 1
fi

if [ ! -f "${PATCH_DIR}/patchmgr" ]; then
  echo "ERROR: patchmgr not found in $PATCH_DIR"
  exit 1
fi

chmod 755 "${PATCH_DIR}/patchmgr"
mkdir -p "$LOG_DIR"

echo "=== CLI DEBUG v1.3.0 - FULL VERBOSE DIAGNOSTICS STARTED ==="
echo "MAA_SSH_KEY = $MAA_SSH_KEY"
echo "PATCH_DIR   = $PATCH_DIR"
echo "NODES       = $(cat "$LIST_FILE" | tr '\n' ' ')"

# === START AGENT AND LOAD KEY ===
eval "$(ssh-agent -s)" > /dev/null 2>&1
echo "SSH_AGENT_PID = $SSH_AGENT_PID"
echo "SSH_AUTH_SOCK = $SSH_AUTH_SOCK"

ssh-add "$MAA_SSH_KEY" > /dev/null 2>&1 || { echo "FATAL: ssh-add FAILED for key $MAA_SSH_KEY"; exit 1; }
echo "=== SSH AGENT + MAA KEY LOADED SUCCESSFULLY (v1.3.0) ==="

echo "=== LOADED KEYS IN AGENT (ssh-add -l) ==="
ssh-add -l || echo "ssh-add -l failed"

# === PER-NODE MANUAL ROOT SSH TEST (VERBOSE ON EVERY NODE) ===
echo "=== MANUAL ROOT SSH TEST TO ALL NODES (FORCED VERBOSE -v) ==="
while read -r node; do
  node=$(echo "$node" | tr -d '\r\n ')
  [ -z "$node" ] && continue
  echo "Testing root@$node (verbose)..."
  ssh -v -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=15 root@"$node" "echo 'SSH SUCCESS as root from $(hostname)'" 2>&1 || true
  echo "  → End of verbose output for $node"
done < "$LIST_FILE"

echo "=== ALL MANUAL TESTS COMPLETE - now running patchmgr with EXPLICIT env forcing ==="

# EXPLICIT env forcing for patchmgr (guarantees agent inheritance)
export SSH_AUTH_SOCK
export SSH_AGENT_PID

cd "$PATCH_DIR"
echo "Running patchmgr manually (CLI debug mode v1.3.0)..."
env SSH_AUTH_SOCK="$SSH_AUTH_SOCK" SSH_AGENT_PID="$SSH_AGENT_PID" ./patchmgr --dbnodes "$LIST_FILE" --upgrade --repo "$REPO_PATH" --target_version "$VERSION" --log_dir "$LOG_DIR" --nobackup

# === POST-RUN FULL LOG DUMP ===
echo "=== PATCHMGR LOG DUMP (patchmgr.trc + patchmgr.log + failing node dbnodeupdate.log) ==="
tail -200 "$LOG_DIR"/patchmgr.trc 2>/dev/null || echo "No patchmgr.trc"
echo "--------------------------------------------------"
tail -200 "$LOG_DIR"/patchmgr.log 2>/dev/null || echo "No patchmgr.log"
echo "--------------------------------------------------"
FAIL_NODE=$(grep -o 'scaqal02adm0[12]' "$LOG_DIR"/patchmgr.log | tail -1 || echo "scaqal02adm02.us.oracle.com")
tail -100 "$LOG_DIR"/"${FAIL_NODE}"_dbnodeupdate.log 2>/dev/null || echo "No ${FAIL_NODE} dbnodeupdate.log"
