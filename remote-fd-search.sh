#!/bin/bash
# Version: 2026-04-02 v2.02
# Changes: Hardcoded PATTERN=emctl + --glob for exact basename match on executables. Debug output shows exact command run. This eliminates ALL SSH quoting/variable-passing failures permanently.
PATTERN="emctl"
THREADS=$(($(nproc) - 8))
echo "[DEBUG fd command] /tmp/fd --threads $THREADS -u -t x -i --glob \"$PATTERN\" /" >&2
nice -n 15 ionice -c3 /tmp/fd --threads "$THREADS" -u -t x -i --glob "$PATTERN" / 2>&1
