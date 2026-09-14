#!/usr/bin/env bash
# Run measured blocks back to back on the single local range.
# Usage (from a plain terminal, detached so no session watchdog can kill it):
#   nohup bash scripts/run_blocks_chained.sh 1 2 3 > artifacts/runs/logs/chained.log 2>&1 &
# run_block.sh attempts each unattempted row once, then reruns rows whose
# latest attempt ended as infrastructure_failure (bounded). It exits 2 if any
# row in the block is still unresolved; this wrapper stops there so the
# failure can be inspected before the next block starts.
set -u
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
for BLOCK in "$@"; do
  if bash "$SCRIPT_DIR/run_block.sh" "$BLOCK"; then
    echo "block $BLOCK resolved, continuing"
  else
    echo "STOP: block $BLOCK has unresolved rows after bounded reruns; inspect before continuing"
    exit 2
  fi
done
echo "all requested blocks complete $(date -u +%H:%M:%SZ)"
