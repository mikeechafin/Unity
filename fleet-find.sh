#!/bin/bash
# Version: 2026-04-02 v1.18
# Changes: Updated to v2.02 wrapper (hardcoded emctl + debug). No other changes.
if [ $# -ne 2 ]; then
  echo "Usage: $0 hosts.txt filename"
  echo "  Example: $0 hosts.txt emctl"
  exit 1
fi

HOSTS_FILE="$1"
FILENAME="$2"

if [ ! -x ./fd ]; then
  echo "Error: ./fd binary missing. Run ./prepare-fd.sh first."
  exit 1
fi

if [ ! -x ./remote-fd-search.sh ]; then
  echo "Error: ./remote-fd-search.sh missing. Create it with the first block above (chmod +x)."
  exit 1
fi

# Clean conflicting host keys once
echo "=== Cleaning known_hosts conflicts ==="
while read -r host; do
  ssh-keygen -R "$host" 2>/dev/null || true
  ssh-keygen -R "$(dig +short "$host" | head -1)" 2>/dev/null || true
done < "$HOSTS_FILE"

echo "=== Searching for '$FILENAME' executables across fleet as root (max 8 concurrent) ==="

cat "$HOSTS_FILE" | xargs -I {} -P 8 -n 1 bash -c '
  HOST="{}"
  echo "=== Starting on root@$HOST ==="

  SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o BatchMode=yes -o ConnectTimeout=30"

  if scp $SSH_OPTS ./fd root@"$HOST":/tmp/fd 2>scp.err && scp $SSH_OPTS ./remote-fd-search.sh root@"$HOST":/tmp/search.sh 2>>scp.err; then
    ssh $SSH_OPTS root@"$HOST" "
      chmod +x /tmp/fd /tmp/search.sh && 
      /tmp/search.sh
      rm -f /tmp/fd /tmp/search.sh 2>/dev/null || true
    " 2>&1 | sed "s/^/[root@$HOST] /"
    echo "=== Finished root@$HOST ==="
  else
    echo "=== SCP FAILED root@$HOST ==="
    cat scp.err
  fi
  rm -f scp.err 2>/dev/null
' 

echo "=== Fleet search for '$FILENAME' complete ==="
